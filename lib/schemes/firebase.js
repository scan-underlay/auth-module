import axios from 'axios'

export default class FirebaseProvider {
  constructor (auth, options) {
    this.$auth = auth
    this.name = options._name

    this.baseUrl = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty'

    this.urls = {
      refresh: `https://securetoken.googleapis.com/v1/token?key=${
        options.apiKey
      }`,
      login: `${this.baseUrl}/verifyPassword?key=${options.apiKey}`,
      reset: `${this.baseUrl}/resetPassword?key=${options.apiKey}`,
      user: `${this.baseUrl}/getAccountInfo?key=${options.apiKey}`,
      user_delete: `${this.baseUrl}/deleteAccount?key=${options.apiKey}`,
      user_update: `${this.baseUrl}/setAccountInfo?key=${options.apiKey}`,
      user_verify: `${this.baseUrl}/getOobConfirmationCode?key=${options.apiKey}`
    }

    auth.firebase = new Firebase(this)

    this.options = options
  }

  set expires (seconds) {
    var date = new Date()
    date.setSeconds(date.getSeconds() + seconds)

    this.$auth.$storage.setCookie('_expires.' + this.name, date.getTime())
  }

  get expires () {
    var timestamp = this.$auth.$storage.getCookie(
      '_expires.' + this.name,
      false
    )
    if (timestamp === false) {
      return 0
    }
    var date = new Date(timestamp * 1)
    var now = new Date()

    var diff = (date.getTime() - now.getTime()) / 1000

    return diff < 0 ? 0 : diff
  }

  mounted () {
    this.$auth.syncToken(this.name)
    this.$auth.syncRefreshToken(this.name)

    if (!process.server) {
      setInterval(async () => {
        if (this.$auth.loggedIn) {
          if (this.expires < 100) {
            this.$auth.firebase.refresh()
          }
        }
      }, 60000)
    }

    return this.$auth.fetchUserOnce()
  }

  async login ({ data }) {
    const loginRequestData = Object.assign({}, {
      returnSecureToken: true
    }, data)
    const response = await axios.post(this.urls.login, loginRequestData)

    if (this.options.requireEmailVerified) {
      const { data } = await axios.post(this.urls.user, {
        idToken: response.data.idToken
      })

      if (data.users[0].disabled) {
        this.logout()
        return Promise.reject(new Error('Please verify user before signing in!'))
      }
    }

    this.expires = response.data.expiresIn

    this.$auth.setToken(this.name, response.data.idToken)
    this.$auth.setRefreshToken(this.name, response.data.refreshToken)

    return this.$auth.fetchUser()
  }

  async fetchUser () {
    if (!this.$auth.getToken(this.name)) {
      return Promise.resolve()
    }

    const { data } = await axios.post(this.urls.user, {
      idToken: this.$auth.getToken(this.name)
    })

    if (data.users[0].disabled) {
      this.logout()
      return Promise.reject(new Error('User has been disabled'))
    }

    this.$auth.setUser({
      uid: data.users[0].localId,

      displayName: data.users[0].displayName,
      email: data.users[0].email,
      emailVerified: data.users[0].emailVerified,
      photoUrl: data.users[0].photoUrl
    })
  }

  async logout () {
    this.$auth.$storage.setCookie('_expires.' + this.name, false)

    return this.$auth.reset()
  }
}

class Firebase {
  constructor (strategy) {
    this.strategy = strategy
  }

  async refresh () {
    var { data } = await axios.post(this.strategy.urls.refresh, {
      grant_type: 'refresh_token',
      refresh_token: this.strategy.$auth.getRefreshToken(this.strategy.name)
    })

    this.strategy.expires = data.expires_in

    this.strategy.$auth.setToken(this.strategy.name, data.id_token)
    this.strategy.$auth.setRefreshToken(this.strategy.name, data.refresh_token)

    return this.strategy.$auth.fetchUser()
  }

  async update (details) {
    if (this.strategy.$auth.loggedIn) {
      const requestData = Object.assign(
        {},
        {
          idToken: this.strategy.$auth.getToken(this.strategy.name),
          returnSecureToken: true
        },
        details
      )
      const { status, data } = await axios.post(
        this.strategy.urls.user_update,
        requestData
      )
      if (status === 200) {
        const newUser = Object.assign({}, this.strategy.$auth.user, {
          displayName: data.displayName,
          photoUrl: data.photoUrl
        })

        this.strategy.expires = data.expiresIn
        this.strategy.$auth.setRefreshToken(
          this.strategy.name,
          data.refreshToken
        )

        this.strategy.$auth.setUser(newUser)

        return this.strategy.$auth.fetchUser()
      }
    }
  }

  async changePassword (password) {
    return this.update({
      password: password
    })
  }

  async changeEmail (email) {
    return this.update({
      email: email
    })
  }

  async sendPasswordReset (email, locale) {
    return axios.post(this.strategy.urls.user_verify, {
      requestType: 'PASSWORD_RESET',
      email: email
    }, {
      headers: {
        'X-Firebase-Locale': locale !== undefined ? locale : 'en'
      }
    })
  }

  async confirmPasswordReset (oobCode, password) {
    return axios.post(this.strategy.urls.reset, {
      oobCode: oobCode,
      newPassword: password
    })
  }

  async sendEmailVerification (locale) {
    if (this.strategy.$auth.loggedIn) {
      return axios.post(this.strategy.urls.user_verify, {
        requestType: 'VERIFY_EMAIL',
        idToken: this.strategy.$auth.getToken(this.strategy.name)
      }, {
        headers: {
          'X-Firebase-Locale': locale !== undefined ? locale : 'en'
        }
      })
    }

    return Promise.reject(new Error('User not found'))
  }

  async verifyEmailVerification (oobCode) {
    return axios.post(this.strategy.urls.user_update, {
      oobCode: oobCode
    })
  }

  async delete () {
    const response = await axios.post(this.strategy.urls.user_delete, {
      idToken: this.strategy.$auth.getToken(this.strategy.name)
    })

    if (response.status === 200) {
      this.strategy.$auth.logout()
    }
  }
}
