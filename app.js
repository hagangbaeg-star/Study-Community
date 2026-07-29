const session = require("express-session");
const db = require("./config/db");
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();


app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    secret: "studycommunity",
    resave: false,
    saveUninitialized: false
}));

app.get("/", (req, res) => {

    res.render("index", {
        user: req.session.user
    });

});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", async (req, res) => {

    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    console.log("회원가입 비밀번호:", password);
    console.log("암호화:", hashedPassword);

    const sql = `
        INSERT INTO users(username, email, password)
        VALUES (?, ?, ?)
    `;

    db.query(
        sql,
        [username, email, hashedPassword],
        (err, result) => {

            if (err) {
                console.log(err);
                return res.send("회원가입 실패");
            }

            res.send("회원가입 성공!");
        }
    );

});

app.post("/login", (req, res) => {

    const { username, password } = req.body;

    const sql = "SELECT * FROM users WHERE username = ?";

    db.query(sql, [username], async (err, result) => {

        if (err) {
            console.log(err);
            return res.send("로그인 실패");
        }

        if (result.length === 0) {
            return res.send("존재하지 않는 아이디입니다.");
        }

        const user = result[0];

        const match = await bcrypt.compare(password, user.password);
        console.log("비교 결과:", match);
        console.log("로그인 입력 비밀번호:", password);
        console.log("DB 비밀번호:", user.password);

        if (!match) {
            return res.send("비밀번호가 틀렸습니다.");
        }

        req.session.user = user;

        res.redirect("/");
    });

});

app.listen(3000, () => {
    console.log("http://localhost:3000");
});

app.get("/logout", (req, res) => {

    req.session.destroy(() => {

        res.redirect("/");

    });

});

app.get("/board", (req, res) => {

    const search = req.query.search;

    let sql = "SELECT * FROM posts";
    let params = [];

    if (search) {
        sql += " WHERE title LIKE ?";
        params.push("%" + search + "%");
    }

    sql += " ORDER BY id DESC";

    db.query(sql, params, (err, result) => {

        if (err) {
            console.log(err);
            return res.send("게시글을 불러올 수 없습니다.");
        }

        res.render("board", {
            posts: result,
            user: req.session.user
        });

    });

});

app.get("/write", (req, res) => {

    if (!req.session.user) {
        return res.redirect("/login");
    }

    res.render("write", {
        user: req.session.user
    });

});

app.post("/write", (req, res) => {

    if (!req.session.user) {
        return res.redirect("/login");
    }

    const { title, content } = req.body;

    const sql = `
        INSERT INTO posts(title, content, writer)
        VALUES (?, ?, ?)
    `;

    db.query(
        sql,
        [title, content, req.session.user.username],
        (err) => {

            if (err) {
                console.log(err);
                return res.send("글 작성 실패");
            }

            res.redirect("/board");

        }
    );

});

app.get("/post/:id", (req, res) => {

    const id = req.params.id;

    db.query(
        "SELECT * FROM posts WHERE id = ?",
        [id],
        (err, result) => {

            if (err) {
                console.log(err);
                return res.send("오류 발생");
            }

            if (result.length === 0) {
                return res.send("게시글이 없습니다.");
            }

            res.render("post", {
                post: result[0],
                user: req.session.user
            });

        }
    );

});

app.get("/edit/:id", (req, res) => {

    if (!req.session.user) {
        return res.redirect("/login");
    }

    db.query(
        "SELECT * FROM posts WHERE id = ?",
        [req.params.id],
        (err, result) => {

            if (err) {
                console.log(err);
                return res.send("오류");
            }

            if (result.length === 0) {
                return res.send("게시글 없음");
            }

            if (result[0].writer !== req.session.user.username) {
                return res.send("수정 권한이 없습니다.");
            }

           res.render("edit", {
            post: result[0],
            user: req.session.user
            });

        }
    );

});

app.post("/edit/:id", (req, res) => {

    const { title, content } = req.body;

    db.query(
        "UPDATE posts SET title=?, content=? WHERE id=?",
        [title, content, req.params.id],
        (err) => {

            if (err) {
                console.log(err);
                return res.send("수정 실패");
            }

            res.redirect("/post/" + req.params.id);

        }
    );

});

app.post("/delete/:id", (req, res) => {

    db.query(
        "DELETE FROM posts WHERE id=?",
        [req.params.id],
        (err) => {

            if (err) {
                console.log(err);
                return res.send("삭제 실패");
            }

            res.redirect("/board");

        }
    );

});

