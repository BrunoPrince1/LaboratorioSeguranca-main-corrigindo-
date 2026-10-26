// XSS sanitiza entradas (texto,email,users,etc)

import { Request, Response } from "express";
import db from "../database";
// Biblioteca que sanitiza textos em JSs e HTML
import xss from "xss";
// Biblioteca para geração de token JWT, que é armazenado como um cookie 
// httpOnly (impedindo leitura via JS), secure (ativo apenas em HTTPS na produção)
// e samesite 'strict' (impedindo sequestro por sites terceiros)
import jwt from "jsonwebtoken";

export const login = async (req: Request, res: Response) => {
    const { email, password } = req.body;

    const query =
                // email e senha substituidos por $1 e $2, previnindo SQL injection
                // nas consultas ao bd
        "SELECT * FROM usuario WHERE email = $1 AND senha = $2";

    console.log(`Query Executada: ${query}`);

    const result = await db.query(query, [email, password]);

    if (result.rowCount && result.rowCount > 0) {

        const usuario = result.rows[0];

        // constante que gera o token JWT com duração programada de 1h, tal token fica em um cookie
        // protegido httpOnly
        const token = jwt.sign(
            {
                id: usuario.id,
                tipo: String(usuario.tipo_usuario_id),
                email: usuario.email,
                nome: usuario.nome
            },
            (global as any).segredoJwt,
            { expiresIn: "1h" }
        );

        res.cookie('token', token, {
            httpOnly: true,                                // JavaScript não consegue ler o cookie
            secure: process.env.NODE_ENV === 'production', // só HTTPS em produção
            sameSite: 'strict',                            // não é enviado em requisições de outros sites
            maxAge: 3600000                                
        });

        res.json({
            success: true,
            user: usuario
        });

    } else {
        res.status(401).json({
            success: false,
            message: "Falha no login"
        });
    }
};


export const novoLogin = async (req: Request, res: Response) => {
    // sanitização e mail e user pelo XSS, a senha não passa pela limpeza XSS pois ela pode
    // remover ou alterar caractéres especiais. A senha nunca é renderizada no html (sendo substituida
    // pelos parametros $1 e $2), ficando imune a SQL injection
    const { password } = req.body;
    const email = xss(String(req.body.email ?? ""));
    const nome = xss(String(req.body.nome ?? ""));

    const queryNomeIpuExiste =
        "SELECT * FROM iptu WHERE nome = $1"; //

    console.log(`Query Executada: ${queryNomeIpuExiste}`);

    const iptuResult = await db.query(queryNomeIpuExiste, [nome]);

    if (iptuResult.rowCount && iptuResult.rowCount > 0) {

        const query =
            // parametros $1, $2 e $3 substituem valores novamente
            `INSERT INTO usuario (email, senha, nome, tipo_usuario_id)
             VALUES ($1, $2, $3, 3)`;

        console.log(`Query Executada: ${query}`);

        const result = await db.query(query, [email, password, nome]);

        const queryIdUsuario =

            `SELECT id FROM usuario  
             WHERE email = $1 AND senha = $2`;

        console.log(`Query Executada: ${queryIdUsuario}`);


        const resultIdUsuario = await db.query(queryIdUsuario, [email, password]);

        const queryUpdateTabelaIptu =
            `UPDATE iptu
             SET usuario_id = $1
             WHERE nome = $2;`

        console.log(`Query Executada: ${queryUpdateTabelaIptu}`);

        const resultUpdate = await db.query(queryUpdateTabelaIptu, [resultIdUsuario.rows[0].id, nome]);

        if (
            result.rowCount &&
            result.rowCount > 0 &&
            resultUpdate.rowCount &&
            resultUpdate.rowCount > 0
        ) {

            res.json({
                success: true,
                user: result.rows[0]

            });

        } else {
            res.status(401).json({
                success: false,
                message: "Falha no login"
            });
        }

    } else {
        // Nome que já passou pelo filtro XSS, seguro.
        res.status(404).json({
            success: false,
            message: `Nome '${nome}' não encontrado no cadastro de municipes`
        });
    }
};


export const atualizarIptu = async (req: Request, res: Response) => {

    const {
        usuarioId,
        novoValor
    } = req.body;

    const query =
        `UPDATE iptu
         SET valor = $1
         WHERE usuario_id = $2`;

    console.log(`Query Executada: ${query}`);

    try {
        await db.query(query, [novoValor, usuarioId]);

        res.json({
            message: "IPTU atualizado"
        });

    } catch (err: any) {
        res.status(500).json({
            error: err.message
        });
    }
};


export const getIptuPorIdUsuario = async (
    req: Request,
    res: Response
) => {

    const {
        usuarioId,
    } = req.body;
    const query =
        `SELECT * FROM iptu WHERE usuario_id = $1`;

    console.log(`Query Executada: ${query}`);

    try {

        const result = await db.query(query, [usuarioId]);

        console.log(`Retorno: ${JSON.stringify(result.rows)}`);

        res.json({
            iptu: result.rows
        });

    } catch (err: any) {

        res.status(500).json({
            error: err.message
        });
    }
};


export const getIptus = async (
    req: Request,
    res: Response
) => {


    const query = `SELECT * FROM iptu`;

    console.log(`Query Executada: ${query}`);

    try {

        const result = await db.query(query);

        res.json({
            iptu: result.rows
        });

    } catch (err: any) {

        res.status(500).json({
            error: err.message
        });
    }
};


export const getQRCodeOrCodBarras = async (
    req: Request,
    res: Response
) => {

    // "as string" nao presente, não força texto, permitindo que parametros cheguem como arrays/objetos
    // 
    const tipo = req.query.tipo;

    // Só aceita codigo de barras ou qrcode, qualquer outro é recusado (Allowlist),
    // melhor segurança que aceitar qualquer valor e "advinhar" e bloquear perigos
    // qualquer xss ou comando dá erro, segurando dados "sujos"
    if (tipo !== "codigoDeBarras" && tipo !== "qrcode") {
        res.status(400).send("Tipo inválido");
        return;
    }


    let codigoHtml = "";

    if (tipo === "codigoDeBarras") {

        codigoHtml =
            `<img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=123456789" />`;

    } else if (tipo === "qrcode") {

        codigoHtml =
            `<img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=QRCodeDemo" />`;
    }

    // Redundancia (output escaping), o "Allowlist" acima já bloqueia valores diferentes na entrada
    // e aqui a saída é higienizada no html antes de devolver a resposta ao usuario, segurança a mais
    // scripts xss
    res.send(`
        <h2>Tipo selecionado: ${xss(tipo)}</h2>
        ${codigoHtml}
    `);
};
