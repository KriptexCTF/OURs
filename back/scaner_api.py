from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from pydantic import BaseModel
from typing import List
from typing import List, Optional
from uvicorn import run
from lib.config_reader import host, port, log_mode
from lib.scan import scan_state_scan, start_scan, create_json
from lib.nmap import nmap_start
from lib.brute.ssh import scan_state_ssh ,initiation_scan
from lib.brute.ftp import scan_state_ftp, initiation_scan as ftp_initiation_scan
from lib.brute.dirfuzz import scan_state_fuzz, initiation_scan as fuzz_initiation_scan
import os
import sys

# -----------------------------
# Общая модель
# -----------------------------
class list_transform(BaseModel):
    targets: List[str]
class ListTransform(BaseModel):
    targets: List[str]
    creds: Optional[str] = None
# -----------------------------
# FastAPI init
# -----------------------------
app = FastAPI(
    title="Network Scanner API",
    description="""
    <b>Сканирование сети, портов и brute force SSH</b>
    
    <i>Доступные API:</i>
    - 🟢 <b>Реальное API:</b> /api/
    - 🧪 <b>Моковое API:</b> /apifake/
    
    <i>Документация:</i>
    - 📚 <b>Swagger UI:</b> /docks
    - 🔄 <b>Перезапуск:</b> /restart
    """,
    version="1.0.0",
    docs_url=None,
)

origins = ["http://localhost", "http://localhost:5173","http://127.0.0.1:5173"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# 📁 Реальный API
# -----------------------------
real_api = APIRouter(prefix="/api", tags=["Real API"])

@real_api.get("/scanallhost",
             summary="Сканировать сеть",
             description="""
             Сканирует указанный IP-диапазон (формат CIDR)
             
             Параметры:
             - `range_ip`: IP-диапазон в формате CIDR (например, 192.168.1.0/24)
             
             Ответ:
             - `results`: Массив найденных хостов с их характеристиками
             """,
             responses={
                 200: {
                     "description": "Успешное сканирование",
                     "content": {
                         "application/json": {
                             "example": {
                                 "results": [
                                     {
                                         "id": "GEYC4MRUFYYTCLRR",
                                         "ip": "10.24.11.1",
                                         "mac": "00:14:1b:26:28:00",
                                         "hostname": None,
                                         "vendor": "Cisco Systems, Inc"
                                     }
                                 ]
                             }
                         }
                     }
                 },
                 400: {"description": "Некорректный запрос"}
             })
async def scan_all_host(range_ip: str):
    if scan_state_scan.is_scanning:
        return {"error": "already_started"}
    output = await start_scan(range_ip)
    return {"results": create_json(output)}

@real_api.get("/get_proc/",
             summary="Прогресс сканирования",
             description="""
             Возвращает текущий процент выполнения сканирования
             
             Возможные ответы:
             - `percent`: Текущий прогресс в процентах (например, "76.54%")
             - `percent`: "done" если сканирование завершено
             - `error`: "scan_disabled" если сканирование не запущено
             """,
             responses={
                 200: {
                     "description": "Прогресс сканирования",
                     "content": {
                         "application/json": {
                             "examples": {
                                 "in_progress": {"value": {"percent": "76.54%"}},
                                 "done": {"value": {"percent": "done"}}
                             }
                         }
                     }
                 }
             })
async def get_proc():
    if scan_state_scan.is_scanning:
        return {"percent": f"{scan_state_scan.procent}"}
    elif scan_state_scan.procent is not None:
        scan_state_scan.procent = None
    return {"percent": "done"}
    

@real_api.post("/scanportsbyid/",
              summary="Сканировать порты",
              description="""
              Сканирует открытые порты для указанных хостов
              
              Параметры:
              - `targets`: Массив ID хостов для сканирования
              
              Ответ:
              - `port_res`: Массив результатов сканирования портов для каждого хоста
              """,
              responses={
                  200: {
                      "description": "Результаты сканирования портов",
                      "content": {
                          "application/json": {
                              "example": {
                                  "port_res": [
                                      {
                                          "id": "GEYC4MRUFYYTCLRR",
                                          "ports": [
                                              {"port": 22, "service": "ssh"},
                                              {"port": 445, "service": "microsoft-ds"}
                                          ]
                                      }
                                  ]
                              }
                          }
                      }
                  },
                  400: {"description": "Некорректный запрос"}
              })
async def scan_ports(request: list_transform):
    result = await nmap_start(request.targets)
    print(result)
    return {"port_res": result}

@real_api.post("/ssh_brute/",
              summary="SSH брутфорс",
              description="""
              Пытается подобрать учетные данные SSH для указанных хостов
              
              Параметры:
              - `targets`: Массив ID хостов для атаки
              
              Ответ:
              - `ssh_res`: Массив результатов подбора учетных данных для каждого хоста
              """,
              responses={
                  200: {
                      "description": "Результаты брутфорса",
                      "content": {
                          "application/json": {
                              "example": {
                                  "ssh_res": [
                                      {
                                          "id": "GEYC4MRUFYYTCLRR",
                                          "users": [
                                              {"username": "maxim", "password": None},
                                              {"username": "kriptex", "password": "44236"}
                                          ]
                                      }
                                  ]
                              }
                          }
                      }
                  },
                  400: {"description": "Некорректный запрос"}
              })
async def ssh_brute(request: list_transform):
    result = await initiation_scan(request.targets)
    return {"ssh_res": result}

@real_api.get("/ssh_proc/")
async def ssh_proc():
    if scan_state_ssh.is_scanning:
        return {"percent": f"{scan_state_ssh.procent}"}
    elif scan_state_ssh.procent is not None:
        scan_state_ssh.procent = None
    return {"percent": "done"}

@real_api.post("/ftp_brute/",
              summary="FTP брутфорс",
              description="""
              Пытается подобрать учетные данные FTP для указанных хостов
              
              Параметры:
              - `targets`: Массив ID хостов для атаки
              
              Ответ:
              - `ftp_res`: Массив результатов подбора учетных данных для каждого хоста
              """,
              responses={
                  200: {
                      "description": "Результаты брутфорса",
                      "content": {
                          "application/json": {
                              "example": {
                                  "ftp_res": [
                                      {
                                          "id": "GEYC4MRUFYYTCLRR",
                                          "users": [
                                              {"username": "anonymous", "password": "anonymous"},
                                              {"username": "admin", "password": "password123"}
                                          ]
                                      }
                                  ]
                              }
                          }
                      }
                  },
                  400: {"description": "Некорректный запрос"}
              })
async def ftp_brute(request: list_transform):
    result = await ftp_initiation_scan(request.targets)
    return {"ftp_res": result}

@real_api.get("/ftp_proc/")
async def ftp_proc():
    if scan_state_ftp.is_scanning:
        return {"percent": f"{scan_state_ftp.procent}"}
    elif scan_state_ftp.procent is not None:
        scan_state_ftp.procent = None
    return {"percent": "done"}

@real_api.post("/dir_fuzz/",
              summary="Фаззинг директорий",
              description="""
              Выполняет фаззинг директорий для указанных хостов
              
              Параметры:
              - `targets`: Массив ID хостов для сканирования вида base32("ip:port")
              - `creds`: Base64-encoded строка вида login:username&&password:P@ssw0rd (опиционально)
              
              Ответ:
              - `fuzz_res`: Массив результатов фаззинга
              """,
              responses={
                  200: {
                      "description": "Результаты фаззинга",
                      "content": {
                          "application/json": {
                              "example": {
                                  "fuzz_res": [
                                      {
                                          "id": "GEYC4MRUFYYTCLRR",
                                          "results": [
                                              {"url": "http://192.168.1.3/admin", "status": 200},
                                              {"url": "http://192.168.1.3/secret", "status": 403}
                                          ]
                                      }
                                  ]
                              }
                          }
                      }
                  },
                  400: {"description": "Некорректный запрос"}
              })
async def dir_fuzz(request: ListTransform):
    result = await fuzz_initiation_scan(request.targets, creds=request.creds)
    return {"fuzz_res": result}

@real_api.get("/fuzz_proc/")
async def fuzz_proc():
    if scan_state_fuzz.is_scanning:
        return {"percent": f"{scan_state_fuzz.procent or '0%'}"}
    elif scan_state_fuzz.procent is not None:
        scan_state_fuzz.procent = None
    return {"percent": "done"}



# -----------------------------
# 🧪 Моковый API
# -----------------------------
fake_api = APIRouter(prefix="/apifake", tags=["Fake API"])

@fake_api.get("/scanallhost/",
             summary="[FAKE] Сканировать сеть",
             description="""
             Возвращает тестовые данные для разработки UI
             
             Всегда возвращает одни и те же моковые данные
             
             Ответ:
             - `results`: Фиксированный массив хостов
             """,
             responses={
                 200: {
                     "description": "Моковые результаты сканирования",
                     "content": {
                         "application/json": {
                             "example": {
                                 "results": [
                                     {
                                         "id": "GEYC4MRUFYYTCLRR",
                                         "ip": "10.24.11.1",
                                         "mac": "00:14:1b:26:28:00",
                                         "hostname": None,
                                         "vendor": "Cisco Systems, Inc"
                                     },
                                     {
                                         "id": "GEYC4MRUFYYTCLRS",
                                         "ip": "10.24.11.2",
                                         "mac": "90:9c:4a:b9:7b:3a",
                                         "hostname": "mbp-vladislav.croc.ru",
                                         "vendor": "Apple, Inc."
                                     }
                                 ]
                             }
                         }
                     }
                 }
             })
async def fake_scan_all_host():
    return {
        "results": [
            {
                "id": "GEYC4MRUFYYTCLRR",
                "ip": "10.24.11.1",
                "mac": "00:14:1b:26:28:00",
                "hostname": None,
                "vendor": "Cisco Systems, Inc"
            },
            {
                "id": "GEYC4MRUFYYTCLRS",
                "ip": "10.24.11.2",
                "mac": "90:9c:4a:b9:7b:3a",
                "hostname": "mbp-vladislav.croc.ru",
                "vendor": "Apple, Inc."
            }
        ]
    }

@fake_api.get("/get_proc/",
             summary="[FAKE] Прогресс сканирования",
             description="""
             Всегда возвращает 76.54% для тестирования
             
             Ответ:
             - `percent`: Фиксированное значение "76.54%"
             """,
             responses={
                 200: {
                     "description": "Фиктивный прогресс сканирования",
                     "content": {
                         "application/json": {
                             "example": {"percent": "76.54%"}
                         }
                     }
                 }
             })
async def fake_get_proc():
    return {"percent": "76.54%"}

@fake_api.post("/scanportsbyid/",
              summary="[FAKE] Сканировать порты",
              description="""
              Возвращает тестовые данные по портам
              
              Параметры:
              - `targets`: Массив ID хостов (игнорируется)
              
              Ответ:
              - `port_res`: Фиксированные данные по портам для каждого хоста
              """,
              responses={
                  200: {
                      "description": "Моковые результаты сканирования портов",
                      "content": {
                          "application/json": {
                              "example": {
                                  "port_res": [
                                      {
                                          "id": "GEYC4MRUFYYTCLRR",
                                          "ports": [
                                              {"port": 22, "service": "ssh"},
                                              {"port": 445, "service": "microsoft-ds"}
                                          ]
                                      }
                                  ]
                              }
                          }
                      }
                  }
              })
async def fake_scan_ports(request: list_transform):
    return {
        "port_res": [
            {
                "id": id,
                "ports": [
                    {"port": 22, "service": "ssh"},
                    {"port": 445, "service": "microsoft-ds"}
                ]
            } for id in request.targets
        ]
    }

@fake_api.post("/ssh_brute/",
              summary="[FAKE] SSH брутфорс",
              description="""
              Тестовые результаты подбора учетных данных
              
              Параметры:
              - `targets`: Массив ID хостов (игнорируется)
              
              Ответ:
              - `ssh_res`: Фиксированные результаты брутфорса для каждого хоста
              """,
              responses={
                  200: {
                      "description": "Моковые результаты брутфорса",
                      "content": {
                          "application/json": {
                              "example": {
                                  "ssh_res": [
                                      {
                                          "id": "GEYC4MRUFYYTCLRR",
                                          "users": [
                                              {"username": "maxim", "password": None},
                                              {"username": "kriptex", "password": "44236"}
                                          ]
                                      }
                                  ]
                              }
                          }
                      }
                  }
              })
async def fake_ssh_brute(request: list_transform):
    return {
        "ssh_res": [
            {
                "id": id,
                "users": [
                    {"username": "maxim", "password": None},
                    {"username": "kriptex", "password": "44236"}
                ]
            } for id in request.targets
        ]
    }

# -----------------------------
# Swagger по адресу /docks
# -----------------------------
@app.get("/docks", include_in_schema=False)
async def custom_swagger_ui():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="📚 Network Scanner API | Swagger UI",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png"
    )

# -----------------------------
# Ручка перезапуска
# -----------------------------
@app.get("/restart", tags=["System"], include_in_schema=False)
async def restart():
    os.execv(sys.executable, ['python'] + sys.argv)

# -----------------------------
# Маршруты и запуск
# -----------------------------
app.include_router(real_api)
app.include_router(fake_api)

def print_routes():
    print(f"\n🚀 FastAPI сервер запущен на http://{host}:{port}")
    print(f"📚 Swagger UI:  http://{host}:{port}/docks")
    print(f"🟢 Реальное API: http://{host}:{port}/api/")
    print(f"🧪 Моковое API:  http://{host}:{port}/apifake/")
    print(f"🔁 Перезапуск:   http://{host}:{port}/restart\n")

if __name__ == "__main__":
    print_routes()
    run(app, host=host, port=port, log_level=log_mode)