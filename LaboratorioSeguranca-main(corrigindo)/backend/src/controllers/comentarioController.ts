
import { Request, Response } from "express";
import db from "../database";
import xss from "xss";


export const criarComentario = async (
    req: Request,
    res: Response
) => {

    const {
        texto,
        usuarioId
    } = req.body;

    // Limpa o texto antes de salvar, String() garante que seja sempre texto
    const textoLimpo = xss(String(texto ?? ""));

    // Valores trocados por $1 e $2
    const query =
        `INSERT INTO comentario (texto, usuario_id)
        VALUES ($1, $2)`;

    console.log(`Query Executada: ${query}`);


    try {

        // Aqui ficam os valores de $1 e $2, já sanitizados
        await db.query(query, [textoLimpo, usuarioId]);

        res.status(201).json({
            message: "Comentário criado"
        });

    } catch (err: any) {

        res.status(500).json({
            error: err.message
        });
    }
};


export const listarComentarios = async (
    _req: Request,
    res: Response
) => {

    try {

        const result = await db.query(
            "SELECT * FROM comentario"
        );

        // Comando que limpa o texto já salvo no bd, evitando comandos a serem executados
        const comentarios = result.rows.map((c) => ({
            ...c,
            texto: xss(c.texto ?? ""),
        }));

        res.json(comentarios);

    } catch (err: any) {

        res.status(500).json({
            error: err.message
        });
    }
};