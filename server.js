const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
// app.set('trust proxy', true);

const SESSION_TTL_MS = 120 * 60 * 1000; // 2시간
const MAX_SESSIONS_PER_DEVICE = 4;

// email -> { deviceKey, profiles: Map(profileId -> { sessionId, ip, ua, last }), lastDeviceSeenAt }
const activeSessions = new Map();

const nowKR = () => new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });

const clientIP = (req) => {
  const xff = req.headers['x-forwarded-for'] || '';
  return (xff.split(',')[0] || '').trim() || req.connection.remoteAddress || '';
};

const clientUA = (req) => String(req.headers['user-agent'] || '').slice(0, 300);

function makeDeviceKey(req) {
  // ✅ "같은 크롬/같은 PC" 판별용 (대략적)
  // - 확장 수정 없이 가능한 최선: IP + User-Agent
  const ip = clientIP(req);
  const ua = clientUA(req);
  return crypto.createHash('sha256').update(`${ip}|${ua}`).digest('hex').slice(0, 24);
}

function pruneExpired(email) {
  const entry = activeSessions.get(email);
  if (!entry) return;

  for (const [pid, s] of entry.profiles.entries()) {
    if (Date.now() - s.last > SESSION_TTL_MS) entry.profiles.delete(pid);
  }
  if (entry.profiles.size === 0) activeSessions.delete(email);
}

app.get('/', (_, res) => res.send('🚀 인증 서버가 실행 중입니다.'));

/**
 * ✅ 로그인 정책
 * - 같은 email이라도 "deviceKey"가 다르면: 기존 세션 전부 삭제(=다른 크롬/다른 PC로 간주 → 팅김)
 * - 같은 deviceKey면: profileId 별 세션 유지
 * - 같은 deviceKey에서 동시 세션 최대 3개 허용
 */
app.all('/auth', (req, res) => {
  const usersPath = path.join(__dirname, 'users.json');
  const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));

  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const code = String(q.code || '').trim();
  const profileId = String(q.profileId || '').trim();

  const ip = clientIP(req);
  const ua = clientUA(req);
  const time = nowKR();
  const deviceKey = makeDeviceKey(req);

  if (!email || !code || !profileId) {
    return res.json({ ok: false, msg: 'email, code, profileId 필요' });
  }

  if (!users[email] || users[email] !== code) {
    console.log(`[실패] 🔴 ${time} | ${email} | IP:${ip}`);
    return res.json({ ok: false, msg: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  }

  pruneExpired(email);

  const cur = activeSessions.get(email);

  // ✅ 다른 디바이스(다른 크롬/프로필/PC로 간주)면 기존 세션 전부 종료
  if (cur && cur.deviceKey !== deviceKey) {
    console.log(`[디바이스 변경 로그아웃] 🚫 ${time} | ${email} | old:${cur.deviceKey} → new:${deviceKey}`);
    activeSessions.delete(email);
  }

  let entry = activeSessions.get(email);
  if (!entry) {
    entry = {
      deviceKey,
      profiles: new Map(),
      lastDeviceSeenAt: Date.now(),
    };
    activeSessions.set(email, entry);
  }

  entry.lastDeviceSeenAt = Date.now();

  // ✅ 같은 디바이스에서 최대 3개까지 허용 (profileId가 이미 있으면 교체/갱신)
  const already = entry.profiles.has(profileId);
  if (!already && entry.profiles.size >= MAX_SESSIONS_PER_DEVICE) {
    console.log(`[세션 제한 초과] ⚠️ ${time} | ${email} | device:${deviceKey} | size:${entry.profiles.size}`);
    return res.json({
      ok: false,
      msg: `해당 아이디는 접속기,보안패스,도우미 ${MAX_SESSIONS_PER_DEVICE}개까지 가능합니다.`,
    });
  }

  const sessionId = 'sess_' + crypto.randomBytes(8).toString('hex');
  entry.profiles.set(profileId, { sessionId, ip, ua, last: Date.now() });

  console.log(`[로그인] 🟢 ${time} | ${email} | 프로필:${profileId} | device:${deviceKey} | IP:${ip}`);
  return res.json({ ok: true, sessionId, profileId, ttlMs: SESSION_TTL_MS });
});

// ✅ 세션 확인
app.get('/check', (req, res) => {
  const email = String(req.query.email || '').trim();
  const profileId = String(req.query.profileId || '').trim();
  if (!email || !profileId) return res.json({ ok: false, msg: 'email, profileId 필요' });

  pruneExpired(email);

  const deviceKey = makeDeviceKey(req);
  const entry = activeSessions.get(email);
  if (!entry) return res.json({ ok: false, expired: true });

  // ✅ 다른 디바이스면 "다른 프로필에서 로그인됨" 케이스로 처리되게 sameProfile:false 내려줌
  if (entry.deviceKey !== deviceKey) {
    return res.json({ ok: false, sameProfile: false, msg: '다른 환경(디바이스)에서 로그인됨' });
  }

  const cur = entry.profiles.get(profileId);
  if (!cur) return res.json({ ok: false, expired: true });

  const valid = Date.now() - cur.last <= SESSION_TTL_MS;
  if (!valid) {
    entry.profiles.delete(profileId);
    if (entry.profiles.size === 0) activeSessions.delete(email);
    return res.json({ ok: false, expired: true });
  }

  return res.json({
    ok: true,
    sameProfile: true,
    sessionId: cur.sessionId,
    expiresInMs: SESSION_TTL_MS - (Date.now() - cur.last),
    concurrent: entry.profiles.size,
    maxConcurrent: MAX_SESSIONS_PER_DEVICE,
  });
});

// ✅ 하트비트(세션 유지)
app.post('/touch', (req, res) => {
  const { email, profileId } = req.body || {};
  if (!email || !profileId) return res.json({ ok: false, msg: 'email, profileId 필요' });

  pruneExpired(String(email).trim());

  const deviceKey = makeDeviceKey(req);
  const entry = activeSessions.get(String(email).trim());
  if (!entry) return res.json({ ok: false, expired: true });

  if (entry.deviceKey !== deviceKey) {
    return res.json({ ok: false, msg: '다른 환경(디바이스)로 인계됨' });
  }

  const cur = entry.profiles.get(String(profileId).trim());
  if (!cur) return res.json({ ok: false, expired: true });

  cur.last = Date.now();
  return res.json({ ok: true });
});

// ✅ 로그아웃 (같은 디바이스+같은 profileId만)
app.all('/logout', (req, res) => {
  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const profileId = String(q.profileId || '').trim();
  if (!email || !profileId) return res.json({ ok: false, msg: 'email, profileId 필요' });

  pruneExpired(email);

  const deviceKey = makeDeviceKey(req);
  const entry = activeSessions.get(email);
  if (!entry) return res.json({ ok: false, msg: '로그인 상태가 아님' });

  if (entry.deviceKey !== deviceKey) {
    return res.json({ ok: false, msg: '다른 환경(디바이스)에서의 로그아웃 요청' });
  }

  if (entry.profiles.has(profileId)) {
    entry.profiles.delete(profileId);
    if (entry.profiles.size === 0) activeSessions.delete(email);
    console.log(`[로그아웃] 🔓 ${nowKR()} | ${email} | 프로필:${profileId} | device:${deviceKey}`);
    return res.json({ ok: true, msg: '로그아웃 완료' });
  }

  return res.json({ ok: false, msg: '로그인 상태가 아니거나 다른 프로필' });
});

app.listen(PORT, () => console.log(`✅ 서버가 포트 ${PORT}에서 실행 중입니다`));
