// framework utilisé par le serveur node
import express from "express";
// permet de lire les variables d'envoronnement contenues dans .env
import dotenv from "dotenv";
// permettre de lire le contenu des cookies
import cookieParser from "cookie-parser";
import cors from "cors";
// permet de préciser ou sont les routes
import routes from "./routes/index.js";
//récupère les connexion à la base de données
import { connectDB } from "./lib/db.js";
// indique que l'on va utiliser .env
dotenv.config();

const PORT = process.env.PORT;
// indique que notre application utilise express
const app = express();

// indique que l'on va pouvoir traduire le JSON et que l'on va utiliser des cookies
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: [process.env.DEPLOY_FRONT_URL, process.env.CLIENT_URL],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-type"],
    credentials: true,
  })
);

// chaque route localhost:3000 sera redirigé vers le dossier routes
app.use("/", routes);

app.listen(PORT, () => {
  console.log(`Le serveur est démarré sur le port ${PORT}`);
  connectDB();
});
