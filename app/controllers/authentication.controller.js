import bcryptjs from "bcryptjs";
import JsonWebToken  from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export const usuarios = [{
    user: "b", emai: "bas@as.com",
    password: "$2a$05$IJLiF2JZ9.j.2zgamFhnxOfpdnVlhuHIZwJKSpXz6S9i3ZGRzPGN6"
}];

async function login(req, res){
    const user = req.body.user;
    const password = req.body.password;
    if(!user || !password){
        return res.status(400).send({status:"Error", message:"Los campos estan incompletos"})
    }
    const usuarioARevisar = usuarios.find(usuario=> usuario.user == user);
    if(!usuarioARevisar){
        return res.status(400).send({status:"Error", message:"Error durante login"})
    }
    const loginCorrecto = await bcryptjs.compare(password, usuarioARevisar.password);
    if (!login){
        return res.status(400).send({status:"Error", message:"Error durante login"})
    }
    const token = JsonWebToken.sign({user:usuarioARevisar.user},
        process.env.JWT_SECRET,
        {expiresIn:process.env.JWT_EXPIRATION});
    
        const cookieOpts = {
            expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
            path: "/"
        };
        res.cookie("jwt",token,cookieOpts);
        res.send({status:"ok", message:"usuario loggeado", redirect:"/admin"})
}

async function register(req, res){
    const user = req.body.user;
    const email = req.body.email;
    const password = req.body.password;
    if(!user || !password || !email){
        return res.status(400).send({status:"Error", message:"Los campos estan incompletos"})
    }
    const usuarioARevisar = usuarios.find(usuario=> usuario.user == user);
    if(usuarioARevisar){
        return res.status(400).send({status:"Error", message:"Este usuario ya existe"})
    }
    const salt = await bcryptjs.genSalt(5);
    const hashPassword = await bcryptjs.hash(password,salt);
    const nuevoUsuario = {
        user,email,password:hashPassword
    }
    usuarios.push(nuevoUsuario);
    return res.status(201).send({status:"ok",message:"usuario ${nuevoUsuario.user} agregado",redirect:"/"})
}

export const methods ={
    login,register
}