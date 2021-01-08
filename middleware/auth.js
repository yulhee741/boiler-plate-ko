const { User } = require('../models/User');

let auth = (req, res, next) => {
    //인증 처리를 하는곳

    //클라이언트 쿠키에서 토큰을 가져온다.
    let token = req.cookies.x_auth;

    //토큰을 복호화한 후 유저를 찾는다.
    User.findByToken(token, (err, user) => {
        if (err) throw err;
        if (!user) return res.json({ isAuth: false, error: true })

        //유저와 토큰 정보 request에 넣어줌
        req.token = token;
        req.user = user;

        next(); //next가 없으면 미들웨어에 갇힘
    })

    //유저가 있으면 인증 O

    // 유저가 없으면 인증 X
}

module.exports = { auth };