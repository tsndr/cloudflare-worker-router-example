const jwt = require('@tsndr/cloudflare-worker-jwt')

module.exports = async (req, res, next) => {
    if (!req.headers.get('Authorization')) {
        res.status = 401
        res.body = 'NO_HEADER'
        return
    }
    const token = req.headers.get('Authorization').replace('Bearer', '').trim()
    if (!token) {
        res.status = 401
        res.body = 'NO_TOKEN'
        return
    }
    const jwtUser = jwt.decode(token)
    if (!jwtUser || !jwtUser.email) {
        res.status = 401
        res.body = 'BAD_TOKEN'
        return
    }
    let user = JSON.parse(await USER.get(jwtUser.email))
    if (user === null) {
        res.status = 401
        res.body = 'NO_USER'
        return
    }
    if (!await jwt.verify(token, `${JWT_SECRET}.${jwtUser.email}.${user.password}`, 'HS512')) {
        res.status = 401
        res.body = 'INVALID_TOKEN'
        return
    }
    req.auth = {
        token,
        email: jwtUser.email,
        user
    }
    await next()
}