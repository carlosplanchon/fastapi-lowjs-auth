#!/usr/bin/env python3

import uvicorn

from auth_backend_api import app


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
