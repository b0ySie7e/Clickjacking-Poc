# CLICKJACKING-POC
Clickjacking PoC Generator

### Verificar headers
```py
python3 clickjacking_poc.py -u http://192.168.1.10 --check-only
```
### Generar PoC completo

```py
python3 clickjacking_poc.py -u http://localhost:8080
```

### Con iframe semi-visible (para ver alineamiento)

```py
python3 clickjacking_poc.py -u http://app.local --opacity 0.5
```

### Personalizar el botón señuelo

```py
python3 clickjacking_poc.py -u http://target.local --decoy-text "Confirmar pago"
```
