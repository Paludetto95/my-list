# app/routes.py
# Adicionada lógica de busca no histórico de tabulações do consultor.

import pandas as pd
import io
from flask import render_template, flash, redirect, url_for, request, Blueprint
from flask_login import login_user, logout_user, current_user, login_required
from app import db
from app.models import User, Lead, Proposta, Banco, Convenio, Situacao, TipoDeOperacao, LeadConsumption, Tabulation
from datetime import datetime, date, time
from sqlalchemy import func, cast, Date, or_
from sqlalchemy.orm import joinedload

bp = Blueprint('main', __name__)

# --- ROTAS DE ADMIN E GERAIS ---
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('main.admin_dashboard'))
        else:
            return redirect(url_for('main.consultor_dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember_me') is not None
        
        user = User.query.filter_by(email=email).first()
        
        if user is None or not user.check_password(password):
            flash('Email ou senha inválidos', 'danger')
            return redirect(url_for('main.login'))
            
        login_user(user, remember=remember)
        
        if user.is_admin:
            return redirect(url_for('main.admin_dashboard'))
        else:
            return redirect(url_for('main.consultor_dashboard'))

    return render_template('login.html', title='Login')


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
    return redirect(url_for('main.consultor_dashboard'))

@bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))
    
    total_leads = db.session.query(Lead.id).count()
    available_leads = db.session.query(Lead.id).filter_by(status='Novo').count()
    in_progress_leads = db.session.query(Lead.id).filter_by(status='Em Atendimento').count()
    tabulated_leads = db.session.query(Lead.id).filter_by(status='Tabulado').count()
    
    chart_data = {
        'total': total_leads,
        'available': available_leads,
        'in_progress': in_progress_leads,
        'tabulated': tabulated_leads
    }

    page_all = request.args.get('page_all', 1, type=int)
    all_leads_query = Lead.query.options(
        joinedload(Lead.consultor), 
        joinedload(Lead.tabulation)
    ).order_by(Lead.data_criacao.desc())
    all_leads = all_leads_query.paginate(page=page_all, per_page=15, error_out=False)

    page_today = request.args.get('page_today', 1, type=int)
    search_query = request.args.get('q', '')
    tabulation_filter = request.args.get('tabulation_filter', '')

    today_start = datetime.combine(date.today(), time.min)
    today_end = datetime.combine(date.today(), time.max)

    todays_query = Lead.query.options(
        joinedload(Lead.consultor), 
        joinedload(Lead.tabulation)
    ).filter(Lead.data_tabulacao >= today_start, Lead.data_tabulacao <= today_end)

    if tabulation_filter:
        todays_query = todays_query.filter(Lead.tabulation_id == int(tabulation_filter))

    if search_query:
        todays_query = todays_query.join(User, Lead.consultor_id == User.id).filter(
            or_(
                Lead.nome_cliente.ilike(f'%{search_query}%'),
                Lead.cpf.ilike(f'%{search_query}%'),
                User.username.ilike(f'%{search_query}%')
            )
        )

    todays_tabulations = todays_query.order_by(Lead.data_tabulacao.desc()).paginate(page=page_today, per_page=15, error_out=False)
    
    all_tabulations = Tabulation.query.order_by(Tabulation.name).all()

    return render_template('admin_dashboard.html', 
                           title='Dashboard do Admin', 
                           all_leads=all_leads, 
                           todays_tabulations=todays_tabulations,
                           all_tabulations=all_tabulations,
                           search_query=search_query,
                           tabulation_filter=tabulation_filter,
                           chart_data=chart_data)

@bp.route('/admin/tabulations')
@login_required
def manage_tabulations():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    tabulations = Tabulation.query.order_by(Tabulation.name).all()
    return render_template('admin/manage_tabulations.html', title="Gerir Tabulações", tabulations=tabulations)

@bp.route('/admin/tabulations/add', methods=['POST'])
@login_required
def add_tabulation():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    name = request.form.get('name')
    color = request.form.get('color')
    if name and color:
        new_tabulation = Tabulation(name=name, color=color)
        db.session.add(new_tabulation)
        try:
            db.session.commit()
            flash('Tabulação criada com sucesso!', 'success')
        except:
            db.session.rollback()
            flash('Essa tabulação já existe.', 'danger')
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/admin/tabulations/delete/<int:id>', methods=['POST'])
@login_required
def delete_tabulation(id):
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    tabulation_to_delete = Tabulation.query.get_or_404(id)
    db.session.delete(tabulation_to_delete)
    db.session.commit()
    flash('Tabulação eliminada com sucesso!', 'success')
    return redirect(url_for('main.manage_tabulations'))

@bp.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    users = User.query.order_by(User.username).all()
    return render_template('admin/manage_users.html', title="Gerir Utilizadores", users=users)

@bp.route('/admin/users/add', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'on'

    if User.query.filter_by(username=username).first():
        flash('Esse nome de utilizador já existe.', 'danger')
        return redirect(url_for('main.manage_users'))
    
    if User.query.filter_by(email=email).first():
        flash('Esse email já está a ser utilizado.', 'danger')
        return redirect(url_for('main.manage_users'))

    new_user = User(username=username, email=email, is_admin=is_admin)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Utilizador criado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

@bp.route('/admin/users/delete/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    
    if id == current_user.id:
        flash('Não pode eliminar a sua própria conta.', 'danger')
        return redirect(url_for('main.manage_users'))

    user_to_delete = User.query.get_or_404(id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('Utilizador eliminado com sucesso!', 'success')
    return redirect(url_for('main.manage_users'))

@bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if not current_user.is_admin:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('main.index'))

    uploaded_file = request.files.get('file')
    if not uploaded_file or uploaded_file.filename == '':
        flash('Nenhum ficheiro selecionado.', 'warning')
        return redirect(url_for('main.admin_dashboard'))

    if not uploaded_file.filename.lower().endswith('.csv'):
        flash('Formato de ficheiro inválido. Por favor, envie um ficheiro .csv.', 'danger')
        return redirect(url_for('main.admin_dashboard'))

    try:
        content = uploaded_file.stream.read().decode("UTF-8")
        stream = io.StringIO(content, newline=None)
        
        if ';' in content.splitlines()[0]:
            df = pd.read_csv(stream, sep=';')
        else:
            df = pd.read_csv(stream, sep=',')

        df.columns = df.columns.str.lower().str.strip()
        
        column_mapping = { 'nome': 'nome_cliente', 'tel': 'telefone' }
        df.rename(columns=column_mapping, inplace=True)
        
        required_columns = ['nome_cliente', 'cpf']
        for col in required_columns:
            if col not in df.columns:
                flash(f'Erro no ficheiro CSV: A coluna obrigatória "{col}" não foi encontrada.', 'danger')
                return redirect(url_for('main.admin_dashboard'))

        leads_adicionados = 0
        leads_ignorados = 0

        for _, row in df.iterrows():
            cpf = str(row['cpf']).strip()
            if not cpf: continue
            if Lead.query.filter_by(cpf=cpf).first():
                leads_ignorados += 1
                continue

            novo_lead = Lead(
                nome_cliente=str(row['nome_cliente']).strip(),
                cpf=cpf,
                telefone=str(row.get('telefone', '')).strip(),
                email=str(row.get('email', '')).strip(),
                produto=str(row.get('produto', '')).strip()
            )
            db.session.add(novo_lead)
            leads_adicionados += 1

        db.session.commit()
        flash(f'{leads_adicionados} leads importados com sucesso! {leads_ignorados} leads já existentes foram ignorados.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro inesperado ao processar o ficheiro: {e}', 'danger')

    return redirect(url_for('main.admin_dashboard'))


# --- ROTAS DO CONSULTOR (ATUALIZADAS) ---

@bp.route('/consultor/dashboard')
@login_required
def consultor_dashboard():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
    
    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    limite_carteira = 100
    vagas_na_carteira = limite_carteira - leads_em_atendimento
    if vagas_na_carteira < 0:
        vagas_na_carteira = 0

    now = datetime.now()
    unlock_time = now.replace(hour=8, minute=55, second=0, microsecond=0)
    time_gate_passed = now >= unlock_time

    start_of_day = datetime.combine(date.today(), time.min)
    action_taken_today = LeadConsumption.query.filter(
        LeadConsumption.user_id == current_user.id,
        LeadConsumption.timestamp >= start_of_day
    ).first() is not None

    # Lógica para o histórico do dia com busca
    search_history = request.args.get('search_history', '')
    today_start = datetime.combine(date.today(), time.min)
    today_end = datetime.combine(date.today(), time.max)
    
    todays_tabulated_query = Lead.query.options(joinedload(Lead.tabulation)).filter(
        Lead.consultor_id == current_user.id,
        Lead.data_tabulacao >= today_start,
        Lead.data_tabulacao <= today_end
    )
    
    if search_history:
        todays_tabulated_query = todays_tabulated_query.filter(
            or_(
                Lead.nome_cliente.ilike(f'%{search_history}%'),
                Lead.telefone.ilike(f'%{search_history}%'),
                Lead.cpf.ilike(f'%{search_history}%')
            )
        )
        
    todays_tabulated_leads = todays_tabulated_query.order_by(Lead.data_tabulacao.desc()).all()

    all_tabulations = Tabulation.query.order_by(Tabulation.name).all()

    return render_template('consultor_dashboard.html', 
                           title='Meu Painel', 
                           vagas_na_carteira=vagas_na_carteira,
                           leads_em_atendimento=leads_em_atendimento,
                           time_gate_passed=time_gate_passed,
                           action_taken_today=action_taken_today,
                           todays_tabulated_leads=todays_tabulated_leads,
                           all_tabulations=all_tabulations,
                           search_history=search_history)

@bp.route('/pegar_leads', methods=['POST'])
@login_required
def pegar_leads():
    if current_user.is_admin:
        flash('Administradores não podem pegar leads.', 'warning')
        return redirect(url_for('main.admin_dashboard'))

    if datetime.now().time() < time(8, 55):
        flash('A liberação de novos leads só começa às 08:55.', 'warning')
        return redirect(url_for('main.consultor_dashboard'))

    start_of_day = datetime.combine(date.today(), time.min)
    action_taken_today = LeadConsumption.query.filter(
        LeadConsumption.user_id == current_user.id,
        LeadConsumption.timestamp >= start_of_day
    ).first() is not None
    
    if action_taken_today:
        flash('Você já completou a sua carteira hoje. Volte amanhã para pegar novos leads.', 'info')
        return redirect(url_for('main.consultor_dashboard'))

    leads_em_atendimento = Lead.query.filter_by(consultor_id=current_user.id, status='Em Atendimento').count()
    limite_carteira = 100
    leads_a_pegar = limite_carteira - leads_em_atendimento

    if leads_a_pegar <= 0:
        flash('A sua carteira de leads já está cheia. Finalize os atendimentos atuais para poder pegar novos leads.', 'info')
        return redirect(url_for('main.consultor_dashboard'))

    leads_disponiveis = Lead.query.filter(
        Lead.status == 'Novo',
        Lead.consultor_id == None
    ).limit(leads_a_pegar).all()

    if not leads_disponiveis:
        flash('Não há novos leads disponíveis no momento. Tente mais tarde.', 'info')
        return redirect(url_for('main.consultor_dashboard'))

    try:
        for lead in leads_disponiveis:
            lead.consultor_id = current_user.id
            lead.status = 'Em Atendimento'
            consumo = LeadConsumption(user_id=current_user.id, lead_id=lead.id)
            db.session.add(consumo)
        
        db.session.commit()
        flash(f'{len(leads_disponiveis)} novos leads foram adicionados à sua carteira!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao atribuir os leads: {e}', 'danger')

    return redirect(url_for('main.consultor_dashboard'))

@bp.route('/atendimento')
@login_required
def atendimento():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
    
    lead_para_atender = Lead.query.filter_by(
        consultor_id=current_user.id, 
        status='Em Atendimento'
    ).first()

    if not lead_para_atender:
        flash('Parabéns, você não tem leads pendentes para atender!', 'success')
        return redirect(url_for('main.consultor_dashboard'))
        
    tabulations = Tabulation.query.order_by(Tabulation.name).all()
    
    return render_template('atendimento.html', 
                           title="Atendimento de Lead", 
                           lead=lead_para_atender, 
                           tabulations=tabulations)

@bp.route('/atender/<int:lead_id>', methods=['POST'])
@login_required
def atender_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    
    if lead.consultor_id != current_user.id:
        flash('Este lead não pertence a você.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))

    tabulation_id = request.form.get('tabulation_id')
    if not tabulation_id:
        flash('Selecione uma opção de tabulação.', 'warning')
        return redirect(url_for('main.atendimento'))

    lead.tabulation_id = int(tabulation_id)
    lead.status = 'Tabulado'
    lead.data_tabulacao = datetime.utcnow()
    
    try:
        db.session.commit()
        flash(f'Lead de {lead.nome_cliente} tabulado com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao tabular o lead: {e}', 'danger')

    return redirect(url_for('main.atendimento'))

@bp.route('/retabulate/<int:lead_id>', methods=['POST'])
@login_required
def retabulate_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    if lead.consultor_id != current_user.id:
        flash('Não pode editar um lead que não é seu.', 'danger')
        return redirect(url_for('main.consultor_dashboard'))

    new_tabulation_id = request.form.get('new_tabulation_id')
    if not new_tabulation_id:
        flash('Selecione uma nova tabulação.', 'warning')
        return redirect(url_for('main.consultor_dashboard'))

    lead.tabulation_id = int(new_tabulation_id)
    lead.data_tabulacao = datetime.utcnow() # Atualiza a data para o momento da edição
    
    try:
        db.session.commit()
        flash(f'Tabulação do lead {lead.nome_cliente} atualizada com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocorreu um erro ao atualizar a tabulação: {e}', 'danger')

    return redirect(url_for('main.consultor_dashboard'))
