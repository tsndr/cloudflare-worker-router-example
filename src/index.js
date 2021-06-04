const Router = require('@tsndr/cloudflare-worker-router')
const token = require('./middlewares/token')
const router = new Router()
const AuthController = require('./controllers/AuthController')

router.cors()

// Auth
router.post('/v1/auth/register', AuthController.register)
router.post('/v1/auth/login', AuthController.login)
router.get('/v1/auth/user', token, AuthController.get)
router.post('/v1/auth/user', token, AuthController.update)
router.delete('/v1/auth/user', token, AuthController.delete)

addEventListener('fetch', event => {
    event.respondWith(router.handle(event))
})