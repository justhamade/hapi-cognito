const Boom = require('@hapi/boom')
const Hoek = require('@hapi/hoek')


exports.plugin = {
  name: 'cognito-lambda',
  pkg: require('../package.json'),
  requirements: {
    hapi: '>=18.0.0'
  },
  register(server, options) {
    const pluginConfig = Hoek.clone(options)
    if (typeof pluginConfig.debug === 'undefined') {
      pluginConfig.debug = false
    }

    server.ext('onPostAuth', function (request, h) {

      if (request._route.settings && request._route.settings.plugins && request._route.settings.plugins.cognito) {
        const routeConfig = request._route.settings.plugins.cognito

        let decoded = null
        if (request.headers.authorization) {
          decoded = jwt.decode(request.headers.authorization.replace('Bearer ', ''))
        }
        if (pluginConfig.debug) console.log('decoded jwt token', decoded)

        if (decoded === null && routeConfig.required == false) {
          if (pluginConfig.debug) console.error('cognito cannot decode jwt token, but it is not required')
          return h.continue()
        }

        if (decoded === null && (routeConfig.required || routeConfig.group || routeConfig.custom)) {
          if (pluginConfig.debug) console.error('cognito cannot decode jwt token, but it is required')
          return h(Boom.unauthorized(null, 'Cognito', null))
        }

        const credentials = {
          username: decoded['cognito:username'],
          firstName: decoded['given_name'],
          lastName: decoded['family_name'],
          email: decoded['email'],
          id: decoded['sub'],
          groups: decoded['cognito:groups'] ? decoded['cognito:groups'] : [],
          hasGroup: function (group) {
            for (let i = 0; i < credentials.groups.length; i++) {
              if (group === credentials.groups[i]) {
                return true
              }
            }
            return false
          }
        }

        request.credentials = credentials
        if (pluginConfig.debug) console.log('cognito credentials', credentials)

        if (routeConfig.group) {
          if (pluginConfig.debug) console.log('cognito group check', routeConfig.group, credentials.groups)
          if (credentials.hasGroup(routeConfig.group)) {
            if (pluginConfig.debug) console.log('cognito group check success')
            return h.continue()
          } else {
            if (pluginConfig.debug) console.log('cognito group check failed')
            return h(Boom.unauthorized(null, 'Cognito', null))
          }
        }

        const callback = function (result, message) {
          if (pluginConfig.debug) console.log('cognito custom callback', result, message)

          if (result) {
            return h.continue()
          } else {
            return h(Boom.forbidden(message))
          }
        }

        if (routeConfig.custom) {
          console.log('cognito custom strategy', typeof routeConfig.custom)
          if (typeof routeConfig.custom === 'function') {
            if (pluginConfig.debug) console.log('cognito custom routeConfig function', result, message)
            routeConfig.custom(request, credentials, callback)
          } else if (typeof routeConfig.custom === 'string') {
            if (pluginConfig.debug) console.log('cognito custom pluginConfig function', routeConfig.custom)
            const fcustom = pluginConfig.custom[routeConfig.custom]
            if (fcustom === null) {
              return h(Boom.badImplementation('not configured correctly, custom authorizer ' + routeConfig.custom + ' not found'))
            } else {
              fcustom(request, credentials, callback)
            }
          }
        } else {
          h.continue()
        }
      } else {
        h.continue()
      }
    })
    next()
  }
}
