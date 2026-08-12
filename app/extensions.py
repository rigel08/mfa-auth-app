from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()

# In-memory storage is fine for a single-instance portfolio deployment.
# For multi-instance production deployments, back this with Redis instead
# (storage_uri="redis://...") so limits are shared across processes.
limiter = Limiter(key_func=get_remote_address)
