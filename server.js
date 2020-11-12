import express from 'express';
import connectDatabase from './config/db';
import { check, validationResult } from 'express-validator';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import config from 'config';
import User from './models/User';
import auth from './middleware/auth';


//Initialize express application
const app = express();

//connect database
connectDatabase();

//configure Middleware
app.use(express.json({ extended: false}));
app.use(
  cors({
    origin: 'http://localhost:3000'
  })
);

//API endpoint
/**
 * @route GET /
 * @desc Test endpoint
 */
 
 app.get('/', (req, res) =>
    res.send('http get request sent to root api endpoint')
 );

 /**
  * @route POST api/users
  * @desc Register user
  */

  app.post(
    '/api/users',       //inpoint path
   [
    check('name', 'Please enter your name')
        .not()
        .isEmpty(),
    check('email', 'Please enter a valid email').isEmail(),
    check('password',
          'Please enter a password with 6 or more characters')
        .isLength({ min: 6})
   ], 
  async (req, res) => {     //call back method
      const errors = validationResult(req);
      if(!errors.isEmpty()){
          return res.status(422).json({ errors: errors.array() });
      } else {
          const { name, email, password } = req.body;
          try {
            //check if user exist
            let user = await User.findOne({ email: email});
            if (user) {
              return res 
                .status(400)
                .json({ error: [{ msg: 'User already exists'}] });
            }

            //create a new user
            user = new User({
              name: name,
              email: email,
              password: password
            });

            //encrypt the password
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);

            //save user to database
            await user.save();
            
            //Generate and return a JWT token
            const payload = {
              user: {
                id: user.id
              }
            };

            jwt.sign(
              payload,
              config.get('jwtSecret'),
              { expiresIn: '10hr' },
              (err, token) => {
                if (err) throw err;
                res.json({ token: token });
              }
            )
          } catch (error) {
            res.status(500).send('Server error');
          }
      }
  }
);
/**
 * @route GET api/auth
 * @desc Authorize user
 */
app.get('/api/auth', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.status(200).json(user);
  } catch (error) {
    res.status(500).send('Unknown server error');
  }
}); 

/**
 * @route POST api/login
 * @desc Login user
 */
app.post(
  '/api/login',
  [
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'A password is required').exists()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    } else {
      const { email, password } = req.body;
      try {
        // Check if user exists
        let user = await User.findOne({ email: email });
        if (!user) {
          return res
            .status(400)
            .json({ errors: [{ msg: 'Invalid email or password' }] });
        }

        // Check password
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          return res
            .status(400)
            .json({ errors: [{ msg: 'Invalid email or password' }] });
        }

        // Generate and return a JWT token
        returnToken(user, res);
      } catch (error) {
        res.status(500).send('Server error');
      }
    }
  }
);

const returnToken = (user, res) => {
  const payload = {
    user: {
      id: user.id
    }
  };

  jwt.sign(
    payload,
    config.get('jwtSecret'),
    { expiresIn: '10hr' },
    (err, token) => {
      if (err) throw err;
      res.json({ token: token });
    }
  );
};

  // Connection listner
  const port = 5000;
  app.listen(port, () => console.log (`Express server running on port ${port}`));
