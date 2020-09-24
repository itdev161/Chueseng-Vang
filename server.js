import express from 'express';
import connectDatabase from './config/db';

const app = express();

connectDatabase();

app.use(express.json({extended: false}));

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
app.post('/api/user', (req, res) => {
    console.log(req.body);
    res.send(req.body);
})

app.listen(3000, () => console.log('Express server running on port 3000'));

