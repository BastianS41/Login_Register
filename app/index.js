import express from "express";
//Fix para _dirname
import path from "path";
import { fileURLToPath } from "url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
import { methods as authentication } from "./controllers/authentication.controller.js";
import exp from "constants";
import { methods as authorizations } from "./middlewares/authorization.js";
import cookieParser from "cookie-parser";

//Server 
const app = express();
 app.set("port",4000);
 app.listen(app.get('port'));
 console.log('Servidor correidno en puerto',app.get('port') );

  //Configuracion
app.use(express.static(__dirname + "/public"));
app.use(express.json());
app.use(cookieParser());

 //Rutas
 app.get("/", authorizations.soloPublico, (req,res)=>res.sendFile(__dirname + "/pages/login.html"))
 app.get("/register", authorizations.soloPublico, (req,res)=>res.sendFile(__dirname + "/pages/register.html"))
 app.get("/admin", authorizations.soloAdmin,(req,res)=>res.sendFile(__dirname + "/pages/admin/admin.html"))
 app.post("/api/register", authentication.register)
 app.post("/api/login", authentication.login)
