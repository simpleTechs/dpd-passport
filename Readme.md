## Auth-Passport Resource

This custom resource type allows you to authorize your users using the powerful [Passport](http://passportjs.org).
Currently, the following methods are supported for authentification:

* **local** (i.e. username + password) - ONLY HTTP-POST METHOD
* **Twitter** (using Api v1.1)
* **Facebook** (using OAuth)
* **GitHub**
* **Google**
* **Dribbble**
* **Weibo**


Others can be implemented easily if Passport supports them.

### Requirements

* deployd (you'd have guessed that, probably :-))
* User-Collection named `users` with at least these custom fields:
```json
    {
        "socialAccount": {
            "name": "socialAccount",
            "type": "string",
            "typeLabel": "string",
            "required": false,
            "id": "socialAccount",
            "order": 0
        },
        "socialAccountId": {
            "name": "socialAccountId",
            "type": "string",
            "typeLabel": "string",
            "required": false,
            "id": "socialAccountId",
            "order": 1
        },
        "profile": {
            "name": "profile",
            "type": "object",
            "typeLabel": "object",
            "required": false,
            "id": "profile",
            "order": 2
        },
        "name": {
            "name": "name",
            "type": "string",
            "typeLabel": "string",
            "required": false,
            "id": "name",
            "order": 3
        }
    }
```
### Notice

In order to avoid the checks for username and password, dpd-passport creates a dummy username and a password hash. That makes it impossible to login locally, but are visible in the deployd backend and **must not be edited**!

#### Updating from v0.3.0 or lower

To avoid error for existing users after the update, every user has to login again before any updates of the user object can be achieved.

### Installation

In your app's root directory, type `npm install dpd-passport` into the command line or [download the source](https://bitbucket.org/simpletechs/dpd-passport). This should create a `dpd-passport` directory in your app's `node_modules` directory.

See [Installing Modules](http://docs.deployd.com/docs/using-modules/installing-modules.md) for details.

### Setup

Open your Dashboard and add the new Passport-Auth Resource. Then configure which modules you want to allow for your users and supply the required information for each module.

Note: You may supply the baseURL (your website's root) via the environment variable `DPD_PASSPORT_BASEURL`. This is especially useful when you have a single codebase for testing + production environments.

### Usage

Point your users to `/auth/{login,twitter,facebook,github,google,dribble,weibo}` to have them login (or signup) via the specified module.
After that, Auth-Passport completely takes over and redirects the users according to the OAuth(2) flow.

Also You can use `/auth/login` to login on local user collection but it has to be POST method.

### Usage in Mobile Apps

Auth-Passport was built with usage in mobile Apps in mind. From inside your mobile app, open a browser and point the user to your website's `/auth/{login,twitter,facebook,github,google,dribble,weibo}` endpoint. From there, Auth-Passport will take over and guide (i.e. redirect) your user through the different steps needed for each provider, until the user has authorized your app and logged in successfully.

Now you can get hold of your user and his session, by specifying a `redirectURL` in the original request. After the login is done (no matter if it was successful or not), your user will be redirected to the specified URL.
Supply some app-specific URL (see your platform's SDK on how that looks) and catch the response in your app.
Auth-Passport will supply the following information:

* **sid** (String) Session ID in deployd, send this in every subsequent request
* **uid** (String) User ID of the user that just logged in
* **success** (Bool) `true`, if login was successfull
* **error** (String) contains the error message in case of an error

### Development

To get started with development, please fork this repository and make your desired changes. Please note that we do all our dev work on bitbucket, so while you may submit pull requests on github, we will only push releases to github once they are finished.

### Credits

We'd like to thank Passport for building this amazing auth-framework!

Auth-Passport is the work of [simpleTechs.net](https://www.simpletechs.net)

### Contributors

The following people contributed some of there valuable spare time to make this module even better. Please add yourself to the list, in case we forgot you.

* [Tristan](https://github.com/tmcnab)
* [Andy](https://github.com/hongkongkiwi)
* [Andrei](https://github.com/andreialecu)
* [Burak](https://github.com/burakcan)
* [Mathis](https://github.com/Maddis1337)
* [Dave](https://github.com/flavordaaave)
