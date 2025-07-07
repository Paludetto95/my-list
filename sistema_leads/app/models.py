# app/models.py
# Adicionado campo 'data_tabulacao' ao modelo Lead.

from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Tabulation(db.Model):
    __tablename__ = 'tabulation'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    color = db.Column(db.String(7), nullable=False, default='#007bff')
    leads = db.relationship('Lead', backref='tabulation', lazy='dynamic')

    def __repr__(self):
        return f'<Tabulation {self.name}>'

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    leads = db.relationship('Lead', backref='consultor', lazy='dynamic')
    propostas = db.relationship('Proposta', backref='consultor', lazy='dynamic')
    leads_consumidos = db.relationship('LeadConsumption', backref='consultor', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Lead(db.Model):
    __tablename__ = 'lead'
    id = db.Column(db.Integer, primary_key=True)
    nome_cliente = db.Column(db.String(140), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False)
    telefone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    produto = db.Column(db.String(140))
    status = db.Column(db.String(50), nullable=False, default='Novo')
    data_criacao = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    consultor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    propostas = db.relationship('Proposta', backref='lead', lazy='dynamic')
    tabulation_id = db.Column(db.Integer, db.ForeignKey('tabulation.id'))
    
    # ESTA LINHA É A CAUSA DO ERRO SE NÃO ESTIVER PRESENTE
    data_tabulacao = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Lead {self.nome_cliente}>'

class LeadConsumption(db.Model):
    __tablename__ = 'lead_consumption'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<LeadConsumption User {self.user_id} -> Lead {self.lead_id}>'

class Proposta(db.Model):
    __tablename__ = 'proposta'
    id = db.Column(db.Integer, primary_key=True)
    valor = db.Column(db.Float, nullable=False)
    data_proposta = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'))
    consultor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    banco_id = db.Column(db.Integer, db.ForeignKey('banco.id'))
    convenio_id = db.Column(db.Integer, db.ForeignKey('convenio.id'))
    situacao_id = db.Column(db.Integer, db.ForeignKey('situacao.id'))
    tipo_operacao_id = db.Column(db.Integer, db.ForeignKey('tipo_de_operacao.id'))

    def __repr__(self):
        return f'<Proposta {self.id}>'

class Banco(db.Model):
    __tablename__ = 'banco'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

class Convenio(db.Model):
    __tablename__ = 'convenio'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

class Situacao(db.Model):
    __tablename__ = 'situacao'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)

class TipoDeOperacao(db.Model):
    __tablename__ = 'tipo_de_operacao'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
