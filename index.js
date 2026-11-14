const net = require('net');
const http = require('http');
const { createClient } = require('@supabase/supabase-js');

// --- CONFIG ---
const HTTP_PORT = process.env.PORT || 3000;
const JT808_PORT = parseInt(process.env.JT808_PORT || '7611', 10);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY env vars!');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const connectedDevices = new Map();

// --- JT808 BINARY HELPERS ---
function unescapePacket(buf) {
  const out = [];
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0x7d && i + 1 < buf.length) {
      if (buf[i + 1] === 0x02) { out.push(0x7e); i++; continue; }
      if (buf[i + 1] === 0x01) { out.push(0x7d); i++; continue; }
    }
    out.push(buf[i]);
  }
  return Buffer.from(out);
}

function escapePacket(buf) {
  const out = [0x7e];
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0x7e) out.push(0x7d, 0x02);
    else if (buf[i] === 0x7d) out.push(0x7d, 0x01);
    else out.push(buf[i]);
  }
  out.push(0x7e);
  return Buffer.from(out);
}

function calcChecksum(buf) {
  let cs = 0;
  for (let i = 0; i < buf.length; i++) cs ^= buf[i];
  return cs;
}

function bcdToString(buf) {
  let s = '';
  for (let i = 0; i < buf.length; i++) {
    s += ((buf[i] >> 4) & 0x0f).toString(10);
    s += (buf[i] & 0x0f).toString(10);
  }
  return s;
}

// Parse JT808 BCD timestamp (YYMMDDHHmmss).
// Note: Most Chinese MDVRs send GMT+8 (+08:00) unless configured to UTC.
function parseBcdTime(buf) {
  const s = bcdToString(buf); // 12 chars: YYMMDDHHmmss
  const iso = `20${s.slice(0, 2)}-${s.slice(2, 4)}-${s.slice(4, 6)}T${s.slice(6, 8)}:${s.slice(8, 10)}:${s.slice(10, 12)}+08:00`;
  const d = new Date(iso);
  return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

function buildResponse(msgId, terminalIdBuf, is2019, serialNum, bodyBuf) {
  const bodyLen = bodyBuf.length;
  let props = bodyLen & 0x03ff;
  if (is2019) props |= 0x4000; // Set bit 14 for JT808-2019

  const headerLen = is2019 ? 17 : 12;
  const header = Buffer.alloc(headerLen);
  header.writeUInt16BE(msgId, 0);
  header.writeUInt16BE(props, 2);

  if (is2019) {
    header.writeUInt8(1, 4); // Protocol version 1
    terminalIdBuf.copy(header, 5, 0, 10);
    header.writeUInt16BE(serialNum & 0xffff, 15);
  } else {
    terminalIdBuf.copy(header, 4, 0, 6);
    header.writeUInt16BE(serialNum & 0xffff, 10);
  }

  const payload = Buffer.concat([header, bodyBuf]);
  const cs = Buffer.from([calcChecksum(payload)]);
  return escapePacket(Buffer.concat([payload, cs]));
}

function buildGeneralAck(terminalIdBuf, is2019, outSerial, inSerial, inMsgId, result = 0) {
  const body = Buffer.alloc(5);
  body.writeUInt16BE(inSerial, 0);
  body.writeUInt16BE(inMsgId, 2);
  body.writeUInt8(result, 4);
  return buildResponse(0x8001, terminalIdBuf, is2019, outSerial, body);
}

function parseLocationBody(body) {
  if (body.length < 28) return null;
  const alarmFlag = body.readUInt32BE(0);
  const statusFlag = body.readUInt32BE(4);

  const accOn = (statusFlag & 0x01) !== 0;
  const isSouth = (statusFlag & 0x04) !== 0;
  const isWest = (statusFlag & 0x08) !== 0;

  let lat = body.readUInt32BE(8) / 1000000;
  let lng = body.readUInt32BE(12) / 1000000;
  if (isSouth) lat = -lat;
  if (isWest) lng = -lng;

  const altitude = body.readUInt16BE(16);
  const speed = body.readUInt16BE(18) / 10; // 0.1 km/h -> km/h
  const heading = body.readUInt16BE(20);
  const recordedAt = parseBcdTime(body.subarray(22, 28));

  // Parse Extra Info TLVs (Mileage, 4G Signal, Satellites)
  let mileageKm = null;
  let signal4g = null;
  let satellites = null;
  let offset = 28;
  while (offset + 2 <= body.length) {
    const id = body.readUInt8(offset);
    const len = body.readUInt8(offset + 1);
    if (offset + 2 + len > body.length) break;
    const val = body.subarray(offset + 2, offset + 2 + len);

    if (id === 0x01 && len === 4) mileageKm = val.readUInt32BE(0) / 10;
    if (id === 0x30 && len === 1) signal4g = val.readUInt8(0);
    if (id === 0x31 && len === 1) satellites = val.readUInt8(0);

    offset += 2 + len;
  }

  return {
    alarmFlag, statusFlag, accOn, lat, lng, altitude,
    speed, heading, recordedAt, mileageKm, signal4g, satellites
  };
}

// --- SUPABASE SYNC ---
async function saveLocation(terminalId, loc) {
  // Ignore invalid 0,0 coordinates if GPS has no lock yet, still update online status
  const hasFix = loc.lat !== 0 && loc.lng !== 0;

  const { data: device, error } = await supabase
    .from('devices')
    .select('id')
    .eq('terminal_id', terminalId)
    .maybeSingle();

  if (error) {
    console.error(`[DB Error] Lookup ${terminalId}:`, error.message);
    return;
  }
  if (!device) {
    console.warn(`[WARN] Unknown terminal_id "${terminalId}" sent GPS. Add it to Supabase 'devices' table!`);
    return;
  }

  const updateData = {
    is_online: true,
    acc_on: loc.accOn,
    last_seen: new Date().toISOString(),
  };

  if (hasFix) {
    updateData.last_lat = loc.lat;
    updateData.last_lng = loc.lng;
    updateData.last_altitude = loc.altitude;
    updateData.last_speed = loc.speed;
    updateData.last_heading = loc.heading;
    updateData.last_gps_at = loc.recordedAt;
  }
  if (loc.mileageKm !== null) updateData.mileage_km = loc.mileageKm;
  if (loc.signal4g !== null) updateData.signal_4g = loc.signal4g;
  if (loc.satellites !== null) updateData.satellites = loc.satellites;

  await supabase.from('devices').update(updateData).eq('id', device.id);

  if (hasFix) {
    await supabase.from('gps_logs').insert({
      device_id: device.id,
      lat: loc.lat,
      lng: loc.lng,
      altitude: loc.altitude,
      speed: loc.speed,
      heading: loc.heading,
      acc_on: loc.accOn,
      mileage_km: loc.mileageKm,
      signal_4g: loc.signal4g,
      satellites: loc.satellites,
      alarm_flag: loc.alarmFlag,
      status_flag: loc.statusFlag,
      recorded_at: loc.recordedAt,
    });
  }

  // Check SOS (bit 0) or Overspeed (bit 1)
  if ((loc.alarmFlag & 0x01) !== 0) {
    await supabase.from('alarms').insert({
      device_id: device.id,
      alarm_type: 'SOS',
      alarm_code: 0,
      severity: 'critical',
      lat: loc.lat,
      lng: loc.lng,
      speed: loc.speed,
      occurred_at: loc.recordedAt,
    });
  }
}

// --- TCP SERVER (JT808) ---
const tcpServer = net.createServer((socket) => {
  let recvBuffer = Buffer.alloc(0);
  let outSerial = 1;
  let currentTerminalId = null;

  console.log(`[TCP] New connection from ${socket.remoteAddress}:${socket.remotePort}`);

  socket.on('data', async (chunk) => {
    recvBuffer = Buffer.concat([recvBuffer, chunk]);

    // Extract complete 0x7E ... 0x7E frames
    while (true) {
      const start = recvBuffer.indexOf(0x7e);
      if (start === -1) { recvBuffer = Buffer.alloc(0); break; }
      const end = recvBuffer.indexOf(0x7e, start + 1);
      if (end === -1) {
        if (start > 0) recvBuffer = recvBuffer.subarray(start);
        break;
      }

      const rawFrame = recvBuffer.subarray(start + 1, end);
      recvBuffer = recvBuffer.subarray(end + 1);

      // Ignore empty frames (happens if two 0x7E sit side-by-side)
      if (rawFrame.length === 0) continue;

      const unescaped = unescapePacket(rawFrame);
      if (unescaped.length < 13) continue;

      const expectedCs = unescaped[unescaped.length - 1];
      const payload = unescaped.subarray(0, unescaped.length - 1);
      if (calcChecksum(payload) !== expectedCs) {
        console.warn('[JT808] Bad checksum, dropping packet');
        continue;
      }

      // Parse Header
      const msgId = payload.readUInt16BE(0);
      const props = payload.readUInt16BE(2);
      const is2019 = (props & 0x4000) !== 0;
      const hasSubPkg = (props & 0x2000) !== 0;

      const tidBuf = is2019 ? payload.subarray(5, 15) : payload.subarray(4, 10);
      const terminalId = bcdToString(tidBuf);
      const inSerial = is2019 ? payload.readUInt16BE(15) : payload.readUInt16BE(10);
      let headerLen = is2019 ? 17 : 12;
      if (hasSubPkg) headerLen += 4;
      const body = payload.subarray(headerLen);

      currentTerminalId = terminalId;
      connectedDevices.set(terminalId, { socket, lastSeen: new Date().toISOString(), is2019 });

      const msgHex = '0x' + msgId.toString(16).padStart(4, '0');

      // Handle Core JT808 Messages
      if (msgId === 0x0100) {
        // Device Register -> Reply 0x8100 with auth token
        console.log(`[JT808] Register (0x0100) from ${terminalId} (v${is2019 ? '2019' : '2013'})`);
        const authToken = Buffer.from('MDVR_AUTH_OK', 'ascii');
        const resBody = Buffer.alloc(3 + authToken.length);
        resBody.writeUInt16BE(inSerial, 0);
        resBody.writeUInt8(0, 2); // 0 = Success
        authToken.copy(resBody, 3);
        socket.write(buildResponse(0x8100, tidBuf, is2019, outSerial++, resBody));

      } else if (msgId === 0x0102) {
        // Device Authentication -> Reply 0x8001
        console.log(`[JT808] Auth (0x0102) from ${terminalId}`);
        socket.write(buildGeneralAck(tidBuf, is2019, outSerial++, inSerial, msgId, 0));
        await supabase.from('devices')
          .update({ is_online: true, protocol_version: is2019 ? '2019' : '2013', last_seen: new Date().toISOString() })
          .eq('terminal_id', terminalId);

      } else if (msgId === 0x0002) {
        // Heartbeat -> Reply 0x8001
        console.log(`[JT808] Heartbeat (0x0002) from ${terminalId}`);
        socket.write(buildGeneralAck(tidBuf, is2019, outSerial++, inSerial, msgId, 0));
        await supabase.from('devices')
          .update({ is_online: true, last_seen: new Date().toISOString() })
          .eq('terminal_id', terminalId);

      } else if (msgId === 0x0200) {
        // Live GPS Location Report
        socket.write(buildGeneralAck(tidBuf, is2019, outSerial++, inSerial, msgId, 0));
        const loc = parseLocationBody(body);
        if (loc) {
          console.log(`[GPS] ${terminalId} -> Lat: ${loc.lat}, Lng: ${loc.lng}, Speed: ${loc.speed} km/h, ACC: ${loc.accOn}`);
          await saveLocation(terminalId, loc);
        }

      } else if (msgId === 0x0704) {
        // Batch GPS Location Report
        socket.write(buildGeneralAck(tidBuf, is2019, outSerial++, inSerial, msgId, 0));
        if (body.length >= 3) {
          const count = body.readUInt16BE(0);
          let pos = 3;
          for (let i = 0; i < count && pos + 2 <= body.length; i++) {
            const itemLen = body.readUInt16BE(pos);
            pos += 2;
            if (pos + itemLen > body.length) break;
            const loc = parseLocationBody(body.subarray(pos, pos + itemLen));
            if (loc) await saveLocation(terminalId, loc);
            pos += itemLen;
          }
          console.log(`[GPS Batch] ${terminalId} uploaded ${count} points`);
        }

      } else {
        // Any other packet (still ACK so MDVR doesn't stall)
        console.log(`[JT808] Unhandled ${msgHex} from ${terminalId} (${body.length} bytes)`);
        socket.write(buildGeneralAck(tidBuf, is2019, outSerial++, inSerial, msgId, 0));
      }
    }
  });

  socket.on('close', async () => {
    console.log(`[TCP] Disconnected: ${currentTerminalId || socket.remoteAddress}`);
    if (currentTerminalId) {
      connectedDevices.delete(currentTerminalId);
      await supabase.from('devices')
        .update({ is_online: false })
        .eq('terminal_id', currentTerminalId);
    }
  });

  socket.on('error', (err) => console.error('[TCP Error]', err.message));
});

tcpServer.listen(JT808_PORT, '0.0.0.0', () => {
  console.log(`JT808 TCP Server listening on 0.0.0.0:${JT808_PORT}`);
});

// --- HTTP SERVER (Railway Healthcheck & Status) ---
const httpServer = http.createServer((req, res) => {
  const list = Array.from(connectedDevices.entries()).map(([id, info]) => ({
    terminal_id: id,
    last_seen: info.lastSeen,
    protocol: info.is2019 ? '2019' : '2013',
  }));
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ status: 'ok', connected_mdvrs: list }, null, 2));
});

httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`HTTP Status Server listening on port ${HTTP_PORT}`);
});
