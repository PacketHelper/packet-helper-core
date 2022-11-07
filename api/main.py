from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse  # noqa

from api.routers.api.create import api as api_create
from api.routers.api.hex import api as api_hex
from api.routers.api.info import api as api_info
from api.routers.api.packets import api as api_packets
from api.routers.version import version

app = FastAPI(
    title="Packet Helper Next",
    description="Packet Helper API helps you to decode hex into packets with description 🚀",
    version="0.1",
    license_info={
        "name": "GPL v2.0",
        "url": "https://github.com/PacketHelper/packet-helper-next/blob/main/LICENSE",
    },
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")

# rest api
router_api_config = {"prefix": "/api", "tags": ["api"]}
for api_router in (api_create, api_hex, api_info, api_packets, version):
    app.include_router(api_router, **router_api_config)

templates = Jinja2Templates(directory="static")


@app.get("/", include_in_schema=False, status_code=status.HTTP_200_OK)
def get_root(request: Request) -> _TemplateResponse:
    """Return Vue single page"""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/hex/{hex_string}", include_in_schema=False, status_code=status.HTTP_200_OK)
def get_hex(request: Request) -> _TemplateResponse:
    """Return specific path for Vue single-page"""
    return templates.TemplateResponse("index.html", {"request": request})
