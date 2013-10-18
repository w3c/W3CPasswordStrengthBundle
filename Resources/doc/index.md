W3CPasswordStrengthBundle
=============================

##Installation

### Get the bundle

Add the following in your composer.json:

``` json
{
    "require": {
        "jean-gui/w3c-password-strength-bundle": "dev-master"
    }
}
```

Or,

``` bash
./composer.phar require jean-gui/w3c-password-strength-bundle dev-master
```

Alternatively, you can point to a specific tag.

### Initialize the bundle

To start using the bundle, register the bundle in your application's kernel class:

``` php
// app/AppKernel.php
public function registerBundles()
{
    $bundles = array(
        // ...
        new W3C\PasswordStrengthBundle\W3CPasswordStrengthBundle(),
    );
)
```


##Usage

If you are using annotations for validations, include the constraints namespace:

``` php
use W3C\PasswordStrengthBundle\Validator\Constraints as W3C;
```

and then add the ```PasswordStrength``` validator to the relevant field:

``` php
/**
 * @W3C\PasswordStrength(minScore=40)
 */
protected $password;
```

Default options include:

- minScore = _40_
