import express from 'express';

const app = express();

const port = 3000;

app.get('/', (req, res) => {
    res.send('Hello Vivek');
})

app.get('/vivek', (req, res) => {
    res.redirect("https://codeforces.com/profile/kvivekcodes");
})

app.listen(port, () => {
    console.log(`Server is running at port: ${port}`);
})  