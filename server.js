const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const mongoose = require('mongoose');

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo';
const MONGO_URI  = process.env.MONGO_URI;

app.use(cors());
app.use(express.json());

// ─── Conexão MongoDB ───────────────────────────────────────────────────────────

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB conectado'))
    .catch(err => { console.error('Erro MongoDB:', err); process.exit(1); });

// ─── Models ───────────────────────────────────────────────────────────────────

const User = mongoose.model('User', new mongoose.Schema({
    username: { type: String, unique: true },
    password: String
}));

const Account = mongoose.model('Account', new mongoose.Schema({
    sessionid:   String,
    ds_user_id:  String,
    username:    String,
    addedBy:     String
}, { strict: false }));

// ─── Auth middleware ───────────────────────────────────────────────────────────

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

app.post('/auth/register', async (req, res) => {
    const { username, password, adminKey } = req.body;
    if (adminKey !== (process.env.ADMIN_KEY || 'mb-admin')) {
        return res.status(403).json({ error: 'Chave de admin incorreta.' });
    }
    if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios.' });
    try {
        const hash = await bcrypt.hash(password, 10);
        await User.create({ username, password: hash });
        res.json({ success: true });
    } catch (err) {
        if (err.code === 11000) return res.status(409).json({ error: 'Usuário já existe.' });
        res.status(500).json({ error: 'Erro interno.' });
    }
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username });
});

// ─── Contas ────────────────────────────────────────────────────────────────────

app.get('/accounts', auth, async (req, res) => {
    const accounts = await Account.find({}, { __v: 0 });
    res.json(accounts);
});

app.post('/accounts', auth, async (req, res) => {
    const account = req.body;
    const isDupe = await Account.findOne(
        account.ds_user_id
            ? { ds_user_id: account.ds_user_id }
            : { sessionid: account.sessionid }
    );
    if (isDupe) return res.status(409).json({ error: 'Conta já cadastrada.' });
    await Account.create({ ...account, addedBy: req.user.username });
    const accounts = await Account.find({}, { __v: 0 });
    res.json({ success: true, accounts });
});

app.delete('/accounts/:id', auth, async (req, res) => {
    const result = await Account.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ error: 'Conta não encontrada.' });
    const accounts = await Account.find({}, { __v: 0 });
    res.json({ success: true, accounts });
});

// ─── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
