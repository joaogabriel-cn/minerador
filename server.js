const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo';
const ADMIN_KEY  = process.env.ADMIN_KEY  || 'mb-admin';

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

app.use(cors());
app.use(express.json());

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
    if (adminKey !== ADMIN_KEY) return res.status(403).json({ error: 'Chave de admin incorreta.' });
    if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios.' });

    const { data: existing } = await supabase.from('users').select('id').eq('username', username).single();
    if (existing) return res.status(409).json({ error: 'Usuário já existe.' });

    const hash = await bcrypt.hash(password, 10);
    const { error } = await supabase.from('users').insert({ username, password: hash });
    if (error) return res.status(500).json({ error: 'Erro ao criar usuário.' });

    res.json({ success: true });
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('username', username).single();
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username });
});

// ─── Contas ────────────────────────────────────────────────────────────────────

app.get('/accounts', auth, async (req, res) => {
    const { data, error } = await supabase.from('accounts').select('*').order('created_at');
    if (error) return res.status(500).json({ error: 'Erro ao buscar contas.' });
    res.json(data);
});

app.post('/accounts', auth, async (req, res) => {
    const account = req.body;

    const query = account.ds_user_id
        ? supabase.from('accounts').select('id').eq('ds_user_id', account.ds_user_id)
        : supabase.from('accounts').select('id').eq('sessionid', account.sessionid);
    const { data: existing } = await query.single();
    if (existing) return res.status(409).json({ error: 'Conta já cadastrada.' });

    const { error } = await supabase.from('accounts').insert({ ...account, added_by: req.user.username });
    if (error) return res.status(500).json({ error: 'Erro ao salvar conta.' });

    const { data } = await supabase.from('accounts').select('*').order('created_at');
    res.json({ success: true, accounts: data });
});

app.delete('/accounts/:id', auth, async (req, res) => {
    const { error } = await supabase.from('accounts').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: 'Erro ao remover conta.' });

    const { data } = await supabase.from('accounts').select('*').order('created_at');
    res.json({ success: true, accounts: data });
});

// ─── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
