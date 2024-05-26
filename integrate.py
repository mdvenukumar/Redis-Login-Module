import redis

r = redis.Redis(host='localhost', port=6379)

r.set('name', 'venu')

# Get the value of the key
value = r.get('name')
print("Value of 'name':", value.decode())
