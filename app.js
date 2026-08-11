require("dotenv").config();

const session = require("express-session");
const db = require("./config/db");
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { google } = require("googleapis");

const app = express();

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    secret: "studycommunity",
    resave: false,
    saveUninitialized: false
}));

// =========================
// Gmail API 설정
// =========================

const oauth2Client = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET
);

oauth2Client.setCredentials({
    refresh_token: process.env.GMAIL_REFRESH_TOKEN
});

const gmail = google.gmail({
    version: "v1",
    auth: oauth2Client
});

// =========================
// Gmail API로 OTP 이메일 보내기
// =========================

async function sendOTPEmail(to, otp) {

    const message =
        `From: ${process.env.GMAIL_USER}\r\n` +
        `To: ${to}\r\n` +
        `Subject: Study Community 이메일 인증번호\r\n` +
        `Content-Type: text/plain; charset="UTF-8"\r\n` +
        `\r\n` +
        `안녕하세요.\r\n\r\n` +
        `Study Community 회원가입 인증번호는 ${otp}입니다.\r\n\r\n` +
        `인증번호는 5분 동안 유효합니다.`;

    const encodedMessage = Buffer
        .from(message, "utf-8")
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

    const result = await gmail.users.messages.send({
        userId: "me",
        requestBody: {
            raw: encodedMessage
        }
    });

    console.log("OTP 이메일 전송 완료");
    console.log("Gmail message ID:", result.data.id);
}

// =========================
// 메인
// =========================

app.get("/", (req, res) => {
    res.render("index", {
        user: req.session.user
    });
});

// =========================
// 로그인
// =========================

app.get("/login", (req, res) => {
    res.render("login");
});

// =========================
// 회원가입 페이지
// =========================

app.get("/register", (req, res) => {
    res.render("register");
});

// =========================
// 회원가입 → OTP 발송
// =========================

app.post("/register", async (req, res) => {

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.send("모든 항목을 입력해주세요.");
    }

    db.query(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        [username, email],
        async (err, result) => {

            if (err) {
                console.log(err);
                return res.send("회원가입 처리 중 오류가 발생했습니다.");
            }

            if (result.length > 0) {
                return res.send("이미 사용 중인 아이디 또는 이메일입니다.");
            }

            try {

                // 비밀번호 암호화
                const hashedPassword = await bcrypt.hash(password, 10);

                // 6자리 OTP
                const otp = crypto
                    .randomInt(100000, 1000000)
                    .toString();

                // 세션에 임시 저장
                req.session.registerData = {
                    username: username,
                    email: email,
                    password: hashedPassword,
                    otp: otp,
                    expires: Date.now() + 5 * 60 * 1000
                };

                // Gmail API로 OTP 발송
                await sendOTPEmail(email, otp);

                res.redirect("/verify-email");

            } catch (error) {

                console.error("OTP 이메일 전송 실패:");
                console.error(error);

                delete req.session.registerData;

                res.send("인증번호 전송에 실패했습니다.");
            }
        }
    );
});

// =========================
// OTP 입력 페이지
// =========================

app.get("/verify-email", (req, res) => {

    if (!req.session.registerData) {
        return res.redirect("/register");
    }

    res.render("verify-email", {
        email: req.session.registerData.email
    });
});

// =========================
// OTP 검증
// =========================

app.post("/verify-email", (req, res) => {

    const { otp } = req.body;

    const data = req.session.registerData;

    if (!data) {
        return res.redirect("/register");
    }

    // 5분 만료
    if (Date.now() > data.expires) {

        delete req.session.registerData;

        return res.send(`
            <h2>인증번호가 만료되었습니다.</h2>
            <a href="/register">회원가입 다시하기</a>
        `);
    }

    // OTP 비교
    if (otp !== data.otp) {

        return res.send(`
            <h2>인증번호가 틀렸습니다.</h2>
            <a href="/verify-email">다시 입력하기</a>
        `);
    }

    // 인증 성공 → DB 저장
    const sql = `
        INSERT INTO users(username, email, password)
        VALUES (?, ?, ?)
    `;

    db.query(
        sql,
        [data.username, data.email, data.password],
        (err) => {

            if (err) {
                console.log(err);
                return res.send("회원가입 처리 중 오류가 발생했습니다.");
            }

            delete req.session.registerData;

            res.send(`
                <h2>🎉 회원가입이 완료되었습니다!</h2>
                <p>이메일 인증이 정상적으로 완료되었습니다.</p>
                <br>
                <a href="/login">로그인하러 가기</a>
            `);
        }
    );
});

// =========================
// 로그인 처리
// =========================

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

        if (!match) {
            return res.send("비밀번호가 틀렸습니다.");
        }

        req.session.user = user;

        res.redirect("/");
    });
});

// =========================
// 로그아웃
// =========================

app.get("/logout", (req, res) => {

    req.session.destroy(() => {
        res.redirect("/");
    });

});

// =========================
// 게시판
// =========================

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

// =========================
// 글쓰기 페이지
// =========================

app.get("/write", (req, res) => {

    if (!req.session.user) {
        return res.redirect("/login");
    }

    res.render("write", {
        user: req.session.user
    });
});

// =========================
// 글쓰기 처리
// =========================

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

// =========================
// 게시글 보기
// =========================

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

// =========================
// 게시글 수정 페이지
// =========================

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

// =========================
// 게시글 수정 처리
// =========================

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

// =========================
// 게시글 삭제
// =========================

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

// =========================
// 서버 실행
// =========================

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`http://localhost:${PORT}`);
});