const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

// Middlewares
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Servir carpeta "public"
app.use(express.static(path.join(__dirname, 'public')));

// Conexión MySQL (ajusta usuario/contraseña según tu instalación)
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',       // ⚠️ cambia si tienes otro usuario
  password: '',       // ⚠️ pon tu password de MySQL
  database: 'miapp'   // ⚠️ crea esta base de datos en MySQL antes
});

db.connect(err => {
  if (err) {
    console.error('Error de conexión a MySQL:', err);
  } else {
    console.log('Conectado a MySQL');
  }
});

// Ruta de registro
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Faltan campos');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      (err, result) => {
        if (err) {
          console.error('Error MySQL:', err); // 👈 verás el error real en la consola
          return res.status(500).send('Error al registrar usuario');
        }
        res.send('Usuario registrado con éxito');
      }
    );
  } catch (error) {
    console.error('Error en bcrypt o query:', error);
    res.status(500).send('Error interno en servidor');
  }
});


// Ruta de login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, results) => {
      if (err) return res.status(500).send('Error en la base de datos');
      if (results.length === 0) return res.status(401).send('Usuario no encontrado');

      const user = results[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match) return res.status(401).send('Contraseña incorrecta');

      res.send('Login exitoso ✅');
    }
  );
});

// Levantar servidor
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`); 
});
