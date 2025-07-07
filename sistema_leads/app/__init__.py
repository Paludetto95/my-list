# app/__init__.py
# ESTE É O ÚNICO ARQUIVO QUE VOCÊ PRECISA ALTERAR.
# Movemos as importações das rotas e modelos para dentro da função create_app.
# Isso quebra o ciclo de importação e resolve o erro.

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from config import Config

# As extensões são inicializadas globalmente, mas sem uma aplicação.
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'main.login' # Define a view de login padrão

def create_app(config_class=Config):
    """
    Fábrica de Aplicação: cria e configura a instância do Flask.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Associa as extensões à instância da aplicação
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Importa e registra o Blueprint DENTRO da função
    # Isso evita a importação circular
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    # A importação dos modelos aqui garante que eles sejam reconhecidos pelo SQLAlchemy
    # e pelo Flask-Migrate quando a aplicação for criada.
    from app import models

    return app
