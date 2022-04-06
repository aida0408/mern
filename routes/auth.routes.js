const {Router} = require('express')
//помогает хэшировать пароли
const bcrypt = require('bcrypt')
const config = require('config')
//для автоизация юзера
const jwt = require('jsonwebtoken')
//для проверки юзера - валидация
const {check, validationResult} = require('express-validator')
const User = require('../models/Users')
const router = Router()

router.post(
    '/register',
    [
        check('email', 'Некорректный email').isEmail(),
        check('password', 'Минимальная длина пароля 6 символов')
            .isLength({min: 6})
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)
            if (errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Некорректные данные при регистрации'
                })
            }
            const {email, password} = req.body
// Проверка емайл адреса
            const candidate = await User.findOne({email})
            if (candidate) {
                return res.status(400).json({message: 'Такой пользователь уже существует!'})
            }
            //хэширование пароля
            const hashPassword = await bcrypt.hash(password, 12)
            //создание нового пользователя
            const user = new User({email, password: hashPassword})
            //сохранить юзера
            await user.save()
            //Пользователь создан

            res.status(201).json({message: 'Пользователь создан'})

        } catch (e) {
            res.status(500).json({message: 'Что-то пошло не так, попробуйте снова!'})
        }


    })
router.post(
    '/login',
    [
        check('email', 'Введите корректный email').normalizeEmail().isEmail(),
        check('password', 'Введите пароль').exists()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)
            if (errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Некорректные данные при входе в систему'
                })
            }
            //логика по созданию юзера
            const {email, password} = req.body
            //найти такого пользователя
            const user = await User.findOne({ email})
            if (!user) {
                return res.status(400).json({message: ' Пользователь не найден'})
            }
            const isMatch = await bcrypt.compare(password, user.password)
            if (!isMatch){
                return res.status(400).json({message: 'Неверный пароль, попробуйте снова!'})
            }
            const token = jwt.sign(
                { userId: user.id},
                config.get('jwtSecret'),
                {expiresIn: 'In'}
            )
            res.json({ token, userId: user.id})

        } catch (e) {
            res.status(500).json({message: 'Что-то пошло не так, попробуйте снова!'})
        }


    })

module.exports = router