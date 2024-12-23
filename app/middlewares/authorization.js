import JsonWebToken from "jsonwebtoken";
import dotenv from "dotenv";
import {usuarios} from "./../controllers/authentication.controller.js";

function soloAdmin(req, res, next) {
    const logueado = revisarCookie(req);
    if (logueado) return next();
    return res.redirect("/");
}

function soloPublico(req, res, next) {
    const logueado = revisarCookie(req);
    if (!logueado) return next();
    return res.redirect("/admin");
}

function revisarCookie(req) {
    try {
        console.log("cookie", req.headers.cookie);

        // Verificar si las cookies están presentes
        if (!req.headers.cookie) {
            console.error("No hay cookies en la solicitud.");
            return false;
        }

        // Buscar la cookie 'jwt'
        const cookieJWT = req.headers.cookie
            .split("; ")
            .find(cookie => cookie.startsWith("jwt="));

        if (!cookieJWT) {
            console.error("La cookie 'jwt' no se encontró.");
            return false;
        }

        // Extraer el valor del token JWT
        const token = cookieJWT.split("=")[1];

        // Decodificar el token
        const decodificada = JsonWebToken.verify(token, process.env.JWT_SECRET);

        // Verificar el usuario
        const usuarioARevisar = usuarios.find(usuario => usuario.user === decodificada.user);

        if (!usuarioARevisar) {
            console.error("El usuario del token no existe.");
            return false;
        }

        return true; // Usuario válido
    } catch (error) {
        console.error("Error al revisar la cookie:", error);
        return false;
    }
}

export const methods = {
    soloAdmin,
    soloPublico
};
