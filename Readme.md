## Auth-Passport Resource

This custom resource type allows you to authorize your users using the powerful [Passport](http://passportjs.org).
Currently, the following methods are supported for authentification:

* local (i.e. username + password)
* Twitter (using Api v1.1)
* Facebook (using OAuth)

Others can be implemented easily if Passport supports them.

### Requirements

* deployd (you'd have guessed that, probably :-))
* User-Collection named `users` with at least these custom fields:
```json
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
```

### Installation

In your app's root directory, type `npm install dpd-passport` into the command line or [download the source](https://bitbucket.org/simpletechs/dpd-passport). This should create a `dpd-passport` directory in your app's `node_modules` directory.

See [Installing Modules](http://docs.deployd.com/docs/using-modules/installing-modules.md) for details.

### Setup

Open your Dashboard and add the new Passport-Auth Resource. Then configure which modules you want to allow for your users and supply the required information for each module.

Note: You may supply the baseURL (your website's root) via the environment variable `DPD_PASSPORT_BASEURL`. This is especially useful when you have a single codebase for testing + production environments.

### Usage

Point your users to `/auth/{login,twitter,facebook}` to have them login (or signup) via the specified module.
After that, Auth-Passport completely takes over and redirects the users according to the OAuth(2) flow.

### Credits

We'd like to thank Passport for building this amazing auth-framework!

Auth-Passport is the work of [simpleTechs.net](https://www.simpletechs.net)