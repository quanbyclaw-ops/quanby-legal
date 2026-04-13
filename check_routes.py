import re
content = open(r'C:\Users\Claw\.openclaw\workspace\quanby-legal\backend\main.py', 'r', encoding='utf-8').read()
routes = re.findall(r'@app\.(get|post|put|delete)\(["\']([^"\']+)', content)
for method, path in routes:
    print(method.upper(), path)
