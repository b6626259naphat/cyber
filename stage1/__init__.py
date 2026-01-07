from flask import Blueprint

stage1_bp = Blueprint('stage1', __name__)

from . import routes
