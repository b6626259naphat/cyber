from flask import Blueprint

stage2_bp = Blueprint('stage2', __name__)

from . import routes
