import express, { json } from "express"
import mysql from "mysql"
import bcrypt from "bcrypt"
import cors from "cors"
import multer from "multer"


const app = express();
const PORT = 5000;

app.use(

cors({

origin: ["http://localhost:3000/", "http://localhost:3000"],

})

);
app.use(express.json());


// Set up Multer storage to handle file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage });



const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'registrationapp',
})

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL database:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});





// CRUD APIS

app.post('/api/register', async(req, res) => {
  const { firstName, lastName, mobileNumber, password_hash } = req.body;
  
  if (!mobileNumber || !password_hash) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  try {

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password_hash, saltRounds);
    

    const checkDuplicateQuery = 'SELECT * FROM registration WHERE mobileNumber = ?';
    const insertQuery = 'INSERT INTO registration (firstName,lastName,mobileNumber,password_hash) VALUES (?, ?, ?, ?)';
    const values = [firstName,lastName,mobileNumber, hashedPassword];

        db.query(checkDuplicateQuery, [mobileNumber], (err, result) => {
            if (err) {
            console.error('Error executing MySQL query:', err);
            return res.status(500).json({ message: 'Internal server error' });
            }
            if (result.length > 0) {
              return res.send({ message: 'Username already exists'})
            }
            db.query(insertQuery, values, (err, result) => {
            if (err) {
                console.error('Error executing MySQL query:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }
            return res.status(201).json({ message: 'Registration successful' });
            });
        });
  } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Internal server error' });
  }


});


app.post('/api/login', (req, res) => {
  const { mobileNumber, password } = req.body;

  if (!mobileNumber || !password) {
    return res.send({ message: 'Username and password are required' });
  }

  const selectQuery = 'SELECT * FROM registration WHERE mobileNumber = ?';

  db.query(selectQuery, [mobileNumber], async (err, result) => {
    if (err) {
      console.error('Error executing MySQL query:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    if (result.length === 0) {
      return res.send({ message: 'Invalid username or password' });
    }

    const user = result[0];

    try {
      const passwordMatch = await bcrypt.compare(password, user.password_hash);
      if (!passwordMatch) {
        return res.send({ message: 'Invalid username or password 2' });
      }
      // Password is correct, authentication successful
      res.status(200).json({ message: 'Authentication successful',user: user });
    } catch (error) {
      console.error('Error comparing passwords:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
});




app.get('/api/register/:id', (req, res) => {
  const registrationId = req.params.id;
  const selectQuery = 'SELECT * FROM registration WHERE id = ?';

  db.query(selectQuery, [registrationId], (err, result) => {
    if (err) {
      console.error('Error executing MySQL query:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: 'Registration not found' });
    }

    res.status(200).json(result[0]);
  });
});




app.put('/api/register/:id', (req, res) => {
  const registrationId = req.params.id;
  const { firstName, lastName, mobileNumber, password_hash } = req.body;

  const updateQuery = 'UPDATE registration SET firstName = ?, lastName = ?, mobileNumber= ? WHERE id = ?';
  const values = [firstName, lastName,mobileNumber,registrationId];

  db.query(updateQuery, values, (err, result) => {
    if (err) {
      console.error('Error executing MySQL query:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Registration not found' });
    }

    res.status(200).json({ message: 'Registration updated successfully' });
  });
});

// Delete a record by ID
app.delete('/api/register/:id', (req, res) => {
  const registrationId = req.params.id;
  const deleteQuery = 'DELETE FROM registration WHERE id = ?';

  db.query(deleteQuery, [registrationId], (err, result) => {
    if (err) {
      console.error('Error executing MySQL query:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Registration not found' });
    }
    res.status(200).json({ message: 'Registration deleted successfully' });
  });
});