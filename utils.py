import requests

def get_ip_location(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        data = response.json()
        if data['status'] == 'success':
            return {
                'lat': data['lat'],
                'lon': data['lon'],
                'city': data['city'],
                'country': data['country']
            }
    except:
        pass
    return None