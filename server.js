const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');
const cors    = require('cors');

const app        = express();
const DATA_DIR   = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ACCS_FILE  = path.join(DATA_DIR, 'accounts.json');
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo';

app.use(cors());
app.use(express.json());

// ─── Helpers ──────────────────────────────────────────────────────────────────

if (!fs.existsSync(DATA_DIR))  fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(ACCS_FILE))  fs.writeFileSync(ACCS_FILE,  '[]');

const read  = f => JSON.parse(fs.readFileSync(f, 'utf8'));
const write = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));

function auth(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token obrigatório.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Token inválido ou expirado.' });
    }
}

// ─── Auth ──────────────────────────────────────────────────────────────────────

// Criar usuário (pode ser chamado uma vez para cadastrar, depois remova ou proteja)
app.post('/auth/register', async (req, res) => {
    const { username, password, adminKey } = req.body;
    if (adminKey !== (process.env.ADMIN_KEY || 'mb-admin')) {
        return res.status(403).json({ error: 'Chave de admin incorreta.' });
    }
    if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios.' });

    const users = read(USERS_FILE);
    if (users.find(u => u.username === username)) {
        return res.status(409).json({ error: 'Usuário já existe.' });
    }

    users.push({ username, password: await bcrypt.hash(password, 10) });
    write(USERS_FILE, users);
    res.json({ success: true });
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = read(USERS_FILE).find(u => u.username === username);
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username });
});

// ─── Contas ────────────────────────────────────────────────────────────────────

app.get('/accounts', auth, (req, res) => {
    res.json(read(ACCS_FILE));
});

app.post('/accounts', auth, (req, res) => {
    const accounts = read(ACCS_FILE);
    const account  = req.body;

    const isDupe = accounts.some(a => {
        if (account.ds_user_id && a.ds_user_id) return a.ds_user_id === account.ds_user_id;
        return a.sessionid === account.sessionid;
    });
    if (isDupe) return res.status(409).json({ error: 'Conta já cadastrada.' });

    accounts.push({ ...account, addedBy: req.user.username });
    write(ACCS_FILE, accounts);
    res.json({ success: true, accounts });
});

app.delete('/accounts/:index', auth, (req, res) => {
    const accounts = read(ACCS_FILE);
    const i = parseInt(req.params.index);
    if (isNaN(i) || i < 0 || i >= accounts.length) {
        return res.status(404).json({ error: 'Conta não encontrada.' });
    }
    accounts.splice(i, 1);
    write(ACCS_FILE, accounts);
    res.json({ success: true, accounts });
});

// ─── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
