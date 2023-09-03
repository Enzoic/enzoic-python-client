# Enzoic Python Client Library

TOC
-
This README covers the following topics:
* [Installation](#installation)
* [The Enzoic Constructor](#the-enzoic-constructor)
* [Passwords API Example](#passwords-api-examples)
* [Credentials API Example](#credentials-api-examples)
* [Exposure API Examples](#exposure-api-examples)
* [Breach Monitoring By User API Examples](#breach-monitoring-by-user-api-examples)
* [Breach Monitoring By Domain API Examples](#breach-monitoring-by-domain-api-examples)
* [Running tests](#running-tests)

## Installation

To Install the library using pip, run:

```sh
$ pip install enzoic
```

## The Enzoic Client

The standard constructor takes your API key and secret you were issued on Enzoic signup.

```python
enzoic = Enzoic("YOUR_API_KEY", "YOUR_API_SECRET")
```
    
If you were instructed to use an alternate API endpoint, you may call the overloaded constructor and pass the base URL
you were provided.

```python
enzoic = Enzoic("YOUR_API_KEY", "YOUR_API_SECRET", "https://api-alt.enzoic.com/v1")
```
## Passwords API Examples

See
https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/passwords-api

```python
# Check whether a password has been compromised
if enzoic.check_password("password_to_test"):
    print("Password is compromised")
else:
    print("Password is not compromised")    
```


## Credentials API Examples


See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api

```python
# Check whether a specific set of credentials are compromised
if enzoic.check_credentials("test@enzoic.com", "password_to_test"):
    print("Credentials are compromised")
else:
    print("Credentials are not compromised")
    
# Use the optional parameters on the check_credentials call to tweak performance 
# by including the date/time of the last check and excluding BCrypt    
if enzoic.check_credentials("test@enzoic.com", "password_to_test", last_check_datetime_object, [PasswordType.Bcrypt]):
    print("Credentials are compromised")
else:
    print("Credentials are not compromised")
```
    
## Exposure API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api

```python
# Get all exposures for a given user
exposures = enzoic.get_exposures_for_user("test@enzoic.com")
print(str(exposures["count"] + " exposures found for test@enzoic.com")

# Now get the full details for the first exposure returned in the exposures response above
details = enzoic.get_exposure_details(exposures["exposures"][0])
print("First exposure for test@enzoic.com was " + details["title"])

# Get all exposures for a given domain - a second parameter indicates whether to include exposure details in results
exposures = enzoic.get_exposures_for_domain('enzoic.com', True, 20, None)
for exposure in exposures["exposures"]:
    
    # print out the first page of results
    print(f'Exposure {exposure["title"]}')
    
# if a pagingToken is present, get the next page of results
if exposures["pagingToken"] != "":
    enzoic.get_exposures_for_domain('enzoic.com', True, 20, exposures["pagingToken"])
    # process the second page of results here

# Get all exposed users for a given domain
# returns paged results
# https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-all-email-addresses-in-a-domain
exposures = enzoic.get_exposed_users_for_domain('enzoic.com', 20, None)
for user in exposures["users"]:

    # print out the first page of results
    print(f'Exposed User: {user["username"]}')
    
# if a pagingToken is present, get the next page of results
if exposures["pagingToken"] != "":
    enzoic.get_exposed_users_for_domain('enzoic.com', 20, exposures["pagingToken"])
    # process the second page of results here
```

## Breach Monitoring By User API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain

```python
# some email addresses you wish to monitor
usernames = ["eicar_0@enzoic.com", "eicar_1@enzoic.com"]

# subscribe for alerts for the above users
add_response = enzoic.add_user_alert_subscriptions(username_hashes=usernames)
print(f'New subscriptions added: {add_response["added"]}')
print(f'Subscriptions that already existed: {add_response["alreadyExisted"]}')

# delete subscriptions for these users
delete_response = enzoic.delete_user_alert_subscriptions(username_hashes=usernames)
print(f'Subscriptions deleted: {delete_response["deleted"]}')
print(f'Subscriptions not found: {delete_response["notFound"]}')

# check whether a user is already subscribed
subscribed = enzoic.is_user_subscribed_for_alerts(username_hash=usernames[0])
if subscribed:
    print(f"User, {usernames[0]}, is already subscribed!")
else:
    print(f"User, {usernames[0]}, is not subscribed!")

# get all users subscribed for alerts on your account
# this call returns paged results per https://www.enzoic.com/docs-exposure-alerts-service-api/#get-exposure-subscriptions
# we can leave the page_size and paging_token parameters empty to get the first page of results
subscriptions_response = enzoic.get_user_alert_subscriptions()
for subscribed_username_hash in subscriptions_response:
    print(f"Username Hash: {subscribed_username_hash}")

# if a pagingToken is present in the response, then get the next page of results
if subscriptions_response["pagingToken"] != "":
    subscriptions_response = enzoic.get_user_alert_subscriptions(paging_token=subscriptions_response["pagingToken"])
    # process results here
```

## Breach Monitoring by Domain API Examples

See https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain

```python
# test domains for alert subscriptions
domains = ["testdomain1.com", "testdomain2.com"]

# subscribe to alerts for these domains
add_response = enzoic.add_domain_alert_subscriptions(domains=domains)
print(f'New subscriptions added: {add_response["added"]}')
print(f'Subscriptions that already existed: {add_response["alreadyExisted"]}')

# delete subscriptions for these domains
delete_response = enzoic.delete_domain_alert_subscriptions(domains=domains)
print(f'Subscriptions deleted: {delete_response["deleted"]}')
print(f'Subscriptions not found: {delete_response["notFound"]}')

# check whether a domain is already subscribed
subscribed = enzoic.is_domain_subscribed_for_alerts(domain=domains[0])
if subscribed:
    print(f"Domain, {domains[0]}, is already subscribed!")
else:
    print(f"Domain, {domains[0]}, is not subscribed!")

# get all domains subscribed for alerts on your account
# this call returns paged results per https://www.enzoic.com/docs-exposure-alerts-service-api/#get-exposure-subscriptions-domains
# we can leave the page_size and paging_token parameters empty to get the first page of results
subscriptions_response = enzoic.get_domain_alert_subscriptions()
for subscribed_domain in subscriptions_response:
    print(f"Domain: {subscribed_domain}")

# if a pagingToken is present in the response, then get the next page of results
if subscriptions_response["pagingToken"] != "":
    subscriptions_response = enzoic.get_domain_alert_subscriptions(paging_token=subscriptions_response["pagingToken"])
    # process results here
```

## Running Tests

If you wish to run tests set your PP_API_KEY and PP_API_SECRET in the pytest.ini file and then run 
```sh
$ pytest ./tests
```

## License

This code is free to use under the terms of the MIT license.