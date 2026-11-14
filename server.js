const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Ensure database file exists
function initDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initialData = {
      settings: {
        isOpen: true,
        scheduleStart: '',
        scheduleEnd: '',
        cycleName: 'جدول الأسبوع (الأحد إلى السبت)'
      },
      users: [
        { id: '1153', name: 'Mohyeldin Azzoz Hosny', password: '123456', role: 'employee' },
        { id: '546', name: 'Yousef Ashraf Saad', password: '123456', role: 'admin' },
        { id: '207', name: 'Wael Melad Nashed Srgyos', password: '123456', role: 'employee' },
        { id: '937', name: 'Ziad Araby Sadek', password: '123456', role: 'employee' }
      ],
      requests: {}
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2), 'utf8');
  }
}

initDB();

function getDB() {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('Error reading DB:', err);
    return { settings: {}, users: [], requests: {} };
  }
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// In-memory sessions
const sessions = new Map();

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    userId: user.id,
    name: user.name,
    role: user.role,
    createdAt: Date.now()
  });
  return token;
}

function getSessionUser(req) {
  let token = null;
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (req.headers['x-auth-token']) {
    token = req.headers['x-auth-token'];
  } else {
    const parsed = url.parse(req.url, true);
    if (parsed.query && parsed.query.token) {
      token = parsed.query.token;
    }
  }

  if (!token || !sessions.has(token)) return null;
  const sess = sessions.get(token);
  const db = getDB();
  const user = db.users.find(u => u.id === sess.userId);
  if (!user) return null;
  return { ...user, token };
}

function isSystemOpen(settings) {
  if (!settings.isOpen) return false;
  const now = new Date();
  if (settings.scheduleStart) {
    const start = new Date(settings.scheduleStart);
    if (now < start) return false;
  }
  if (settings.scheduleEnd) {
    const end = new Date(settings.scheduleEnd);
    if (now > end) return false;
  }
  return true;
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function serveStatic(req, res, filePath) {
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
  });
}

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(data));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    req.setEncoding('utf8');
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) {
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function xmlEscape(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-auth-token'
    });
    res.end();
    return;
  }

  if (pathname.startsWith('/api/')) {
    try {
      if (pathname === '/api/auth/login' && method === 'POST') {
        const { id, password } = await parseBody(req);
        const db = getDB();
        const user = db.users.find(u => String(u.id).trim() === String(id).trim());
        if (!user || user.password !== String(password).trim()) {
          return sendJSON(res, 401, { error: 'كود الموظف أو كلمة المرور غير صحيحة' });
        }
        const token = createSession(user);
        return sendJSON(res, 200, {
          token,
          user: { id: user.id, name: user.name, role: user.role }
        });
      }

      if (pathname === '/api/auth/change-password' && method === 'POST') {
        const currentUser = getSessionUser(req);
        if (!currentUser) return sendJSON(res, 401, { error: 'غير مصرح بالدخول' });

        const { oldPassword, newPassword } = await parseBody(req);
        if (!newPassword || newPassword.trim().length < 4) {
          return sendJSON(res, 400, { error: 'كلمة المرور يجب أن لا تقل عن 4 خانات' });
        }

        const db = getDB();
        const user = db.users.find(u => u.id === currentUser.id);
        if (!user || user.password !== String(oldPassword)) {
          return sendJSON(res, 400, { error: 'كلمة المرور الحالية غير صحيحة' });
        }

        user.password = String(newPassword);
        saveDB(db);
        return sendJSON(res, 200, { message: 'تم تغيير كلمة المرور بنجاح' });
      }

      if (pathname === '/api/system/status' && method === 'GET') {
        const db = getDB();
        const isOpen = isSystemOpen(db.settings);
        return sendJSON(res, 200, {
          settings: db.settings,
          isOpen,
          serverTime: new Date().toISOString()
        });
      }

      if (pathname === '/api/my-request' && method === 'GET') {
        const currentUser = getSessionUser(req);
        if (!currentUser) return sendJSON(res, 401, { error: 'غير مصرح بالدخول' });

        const db = getDB();
        const myRequest = db.requests[currentUser.id] || null;
        const isOpen = isSystemOpen(db.settings);

        return sendJSON(res, 200, {
          request: myRequest,
          isOpen,
          user: { id: currentUser.id, name: currentUser.name, role: currentUser.role }
        });
      }

      if (pathname === '/api/my-request' && method === 'POST') {
        const currentUser = getSessionUser(req);
        if (!currentUser) return sendJSON(res, 401, { error: 'غير مصرح بالدخول' });

        const db = getDB();
        const isOpen = isSystemOpen(db.settings);

        if (!isOpen && currentUser.role !== 'admin') {
          return sendJSON(res, 403, { error: 'عذراً، استقبال الريكويستات مغلق حالياً' });
        }

        const { shifts, notes } = await parseBody(req);
        if (!shifts || typeof shifts !== 'object') {
          return sendJSON(res, 400, { error: 'بيانات الشيفتات غير مكتملة' });
        }

        const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        for (const d of days) {
          if (!shifts[d]) {
            return sendJSON(res, 400, { error: `يرجى اختيار شيفت أو إجازة ليوم ${d}` });
          }
        }

        db.requests[currentUser.id] = {
          userId: currentUser.id,
          userName: currentUser.name,
          shifts,
          notes: notes || '',
          submittedAt: new Date().toISOString(),
          updatedBy: currentUser.name
        };

        saveDB(db);
        return sendJSON(res, 200, {
          message: 'تم حفظ الريكويست وتأكيده بنجاح',
          request: db.requests[currentUser.id]
        });
      }

      if (pathname === '/api/admin/requests' && method === 'GET') {
        const currentUser = getSessionUser(req);
        if (!currentUser || currentUser.role !== 'admin') {
          return sendJSON(res, 403, { error: 'صلاحيات غير كافية' });
        }

        const db = getDB();
        const result = db.users.map(u => ({
          userId: u.id,
          userName: u.name,
          role: u.role,
          request: db.requests[u.id] || null
        }));

        return sendJSON(res, 200, {
          cycleName: db.settings.cycleName,
          isOpen: isSystemOpen(db.settings),
          settings: db.settings,
          roster: result
        });
      }

      if (pathname === '/api/admin/system/status' && method === 'POST') {
        const currentUser = getSessionUser(req);
        if (!currentUser || currentUser.role !== 'admin') {
          return sendJSON(res, 403, { error: 'صلاحيات غير كافية' });
        }

        const body = await parseBody(req);
        const db = getDB();

        db.settings = {
          ...db.settings,
          isOpen: body.isOpen !== undefined ? Boolean(body.isOpen) : db.settings.isOpen,
          scheduleStart: body.scheduleStart !== undefined ? body.scheduleStart : db.settings.scheduleStart,
          scheduleEnd: body.scheduleEnd !== undefined ? body.scheduleEnd : db.settings.scheduleEnd,
          cycleName: body.cycleName || db.settings.cycleName
        };

        saveDB(db);
        return sendJSON(res, 200, {
          message: 'تم تحديث إعدادات النظام بنجاح',
          settings: db.settings,
          isOpen: isSystemOpen(db.settings)
        });
      }

      if (pathname === '/api/admin/requests' && method === 'POST') {
        const currentUser = getSessionUser(req);
        if (!currentUser || currentUser.role !== 'admin') {
          return sendJSON(res, 403, { error: 'صلاحيات غير كافية' });
        }

        const { userId, shifts, notes } = await parseBody(req);
        const db = getDB();
        const targetUser = db.users.find(u => String(u.id) === String(userId));
        if (!targetUser) return sendJSON(res, 404, { error: 'الموظف غير موجود' });

        db.requests[targetUser.id] = {
          userId: targetUser.id,
          userName: targetUser.name,
          shifts,
          notes: notes || '',
          submittedAt: new Date().toISOString(),
          updatedBy: `الآدمن (${currentUser.name})`
        };

        saveDB(db);
        return sendJSON(res, 200, {
          message: `تم تعديل ريكويست الموظف ${targetUser.name} بنجاح`,
          request: db.requests[targetUser.id]
        });
      }

      if (pathname === '/api/admin/users' && method === 'GET') {
        const currentUser = getSessionUser(req);
        if (!currentUser || currentUser.role !== 'admin') {
          return sendJSON(res, 403, { error: 'صلاحيات غير كافية' });
        }
        const db = getDB();
        return sendJSON(res, 200, { users: db.users.map(u => ({ id: u.id, name: u.name, role: u.role })) });
      }

      if (pathname === '/api/admin/users/reset-password' && method === 'POST') {
        const currentUser = getSessionUser(req);
        if (!currentUser || currentUser.role !== 'admin') {
          return sendJSON(res, 403, { error: 'صلاحيات غير كافية' });
        }
        const { userId } = await parseBody(req);
        const db = getDB();
        const targetUser = db.users.find(u => String(u.id) === String(userId));
        if (!targetUser) return sendJSON(res, 404, { error: 'الموظف غير موجود' });

        targetUser.password = '123456';
        saveDB(db);
        return sendJSON(res, 200, { message: `تمت إعادة تعيين كلمة مرور ${targetUser.name} إلى 123456 بنجاح` });
      }

      if (pathname === '/api/admin/users' && method === 'POST') {
        const currentUser = getSessionUser(req);
        if (!currentUser || currentUser.role !== 'admin') {
          return sendJSON(res, 403, { error: 'صلاحيات غير كافية' });
        }
        const { id, name, role } = await parseBody(req);
        if (!id || !name) return sendJSON(res, 400, { error: 'يرجى إدخال كود واسم الموظف' });

        const db = getDB();
        if (db.users.find(u => String(u.id) === String(id).trim())) {
          return sendJSON(res, 400, { error: 'كود الموظف مسجل بالفعل' });
        }

        db.users.push({
          id: String(id).trim(),
          name: name.trim(),
          password: '123456',
          role: role === 'admin' ? 'admin' : 'employee'
        });

        saveDB(db);
        return sendJSON(res, 200, { message: 'تمت إضافة الموظف بنجاح' });
      }

      if (pathname === '/api/admin/export-excel' && method === 'GET') {
        const currentUser = getSessionUser(req);
        if (!currentUser || currentUser.role !== 'admin') {
          return sendJSON(res, 403, { error: 'صلاحيات غير كافية' });
        }

        const db = getDB();
        const cycleName = db.settings.cycleName || 'الأسبوع الحالي';
        const dayKeys = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        const dayNamesArabic = ['الأحد', 'الإثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة', 'السبت'];

        let xml = `<?xml version="1.0" encoding="utf-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
 <Styles>
  <Style ss:ID="Default" ss:Name="Normal"><Alignment ss:Vertical="Center" ss:Horizontal="Center"/><Font ss:FontName="Segoe UI" ss:Size="11"/></Style>
  <Style ss:ID="Header"><Alignment ss:Vertical="Center" ss:Horizontal="Center"/><Font ss:FontName="Segoe UI" ss:Size="12" ss:Color="#FFFFFF" ss:Bold="1"/><Interior ss:Color="#1E3A8A" ss:Pattern="Solid"/></Style>
  <Style ss:ID="Title"><Alignment ss:Vertical="Center" ss:Horizontal="Center"/><Font ss:FontName="Segoe UI" ss:Size="16" ss:Color="#1E3A8A" ss:Bold="1"/></Style>
  <Style ss:ID="SubTitle"><Alignment ss:Vertical="Center" ss:Horizontal="Center"/><Font ss:FontName="Segoe UI" ss:Size="11" ss:Color="#475569" ss:Italic="1"/></Style>
  <Style ss:ID="CellBorder"><Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#E2E8F0"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#E2E8F0"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#E2E8F0"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#E2E8F0"/></Borders><Font ss:FontName="Segoe UI" ss:Size="11"/></Style>
  <Style ss:ID="DayOff"><Alignment ss:Vertical="Center" ss:Horizontal="Center"/><Font ss:FontName="Segoe UI" ss:Size="11" ss:Color="#92400E" ss:Bold="1"/><Interior ss:Color="#FEF3C7" ss:Pattern="Solid"/></Style>
  <Style ss:ID="Annual"><Alignment ss:Vertical="Center" ss:Horizontal="Center"/><Font ss:FontName="Segoe UI" ss:Size="11" ss:Color="#5B21B6" ss:Bold="1"/><Interior ss:Color="#EDE9FE" ss:Pattern="Solid"/></Style>
  <Style ss:ID="Shift"><Alignment ss:Vertical="Center" ss:Horizontal="Center"/><Font ss:FontName="Segoe UI" ss:Size="11" ss:Color="#0369A1" ss:Bold="1"/><Interior ss:Color="#F0F9FF" ss:Pattern="Solid"/></Style>
  <Style ss:ID="Pending"><Alignment ss:Vertical="Center" ss:Horizontal="Center"/><Font ss:FontName="Segoe UI" ss:Size="10" ss:Color="#94A3B8" ss:Italic="1"/></Style>
 </Styles>
 <Worksheet ss:Name="جدول الشيفتات">
  <Table ss:DefaultRowHeight="24">
   <Column ss:Width="70"/><Column ss:Width="160"/><Column ss:Width="100"/><Column ss:Width="100"/><Column ss:Width="100"/><Column ss:Width="100"/><Column ss:Width="100"/><Column ss:Width="100"/><Column ss:Width="100"/><Column ss:Width="150"/><Column ss:Width="130"/>
   <Row ss:Height="30"><Cell ss:MergeAcross="10" ss:StyleID="Title"><Data ss:Type="String">جدول ريكويستات الشيفتات والإجازات - ${xmlEscape(cycleName)}</Data></Cell></Row>
   <Row ss:Height="20"><Cell ss:MergeAcross="10" ss:StyleID="SubTitle"><Data ss:Type="String">تاريخ استخراج التقرير: ${new Date().toLocaleString('ar-EG')}</Data></Cell></Row>
   <Row ss:Height="10"/>
   <Row ss:Height="28">
    <Cell ss:StyleID="Header"><Data ss:Type="String">الكود (ID)</Data></Cell>
    <Cell ss:StyleID="Header"><Data ss:Type="String">اسم الموظف</Data></Cell>
    ${dayNamesArabic.map(d => `<Cell ss:StyleID="Header"><Data ss:Type="String">${d}</Data></Cell>`).join('\n    ')}
    <Cell ss:StyleID="Header"><Data ss:Type="String">ملاحظات</Data></Cell>
    <Cell ss:StyleID="Header"><Data ss:Type="String">حالة التقديم</Data></Cell>
   </Row>
`;

        db.users.forEach(u => {
          const reqItem = db.requests[u.id];
          xml += `   <Row ss:Height="26">\n`;
          xml += `    <Cell ss:StyleID="CellBorder"><Data ss:Type="String">${xmlEscape(u.id)}</Data></Cell>\n`;
          xml += `    <Cell ss:StyleID="CellBorder"><Data ss:Type="String">${xmlEscape(u.name)}</Data></Cell>\n`;

          if (reqItem && reqItem.shifts) {
            dayKeys.forEach(dk => {
              const val = reqItem.shifts[dk] || '-';
              let styleId = 'Shift';
              if (val.toLowerCase() === 'day off') styleId = 'DayOff';
              else if (val.toLowerCase() === 'annual') styleId = 'Annual';
              xml += `    <Cell ss:StyleID="${styleId}"><Data ss:Type="String">${xmlEscape(val)}</Data></Cell>\n`;
            });
            xml += `    <Cell ss:StyleID="CellBorder"><Data ss:Type="String">${xmlEscape(reqItem.notes || '-')}</Data></Cell>\n`;
            xml += `    <Cell ss:StyleID="CellBorder"><Data ss:Type="String">تم التقديم</Data></Cell>\n`;
          } else {
            for (let i = 0; i < 7; i++) xml += `    <Cell ss:StyleID="Pending"><Data ss:Type="String">-</Data></Cell>\n`;
            xml += `    <Cell ss:StyleID="Pending"><Data ss:Type="String">-</Data></Cell>\n`;
            xml += `    <Cell ss:StyleID="Pending"><Data ss:Type="String">لم يقدم بعد</Data></Cell>\n`;
          }
          xml += `   </Row>\n`;
        });

        xml += `  </Table>\n </Worksheet>\n</Workbook>`;

        res.writeHead(200, {
          'Content-Type': 'application/vnd.ms-excel; charset=utf-8',
          'Content-Disposition': `attachment; filename="Shift_Requests_${Date.now()}.xls"`
        });
        res.end(xml);
        return;
      }

      return sendJSON(res, 404, { error: 'API route not found' });
    } catch (err) {
      console.error('Server API error:', err);
      return sendJSON(res, 500, { error: 'Internal Server Error' });
    }
  }

  let reqPath = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.join(PUBLIC_DIR, reqPath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  serveStatic(req, res, filePath);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
