from flask import Blueprint

stage3_bp = Blueprint('stage3', __name__)

from . import routes
