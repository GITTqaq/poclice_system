from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import db, User, Incident, Notice, SystemLink, Case, Document, Message, SystemConfig, AuditLog, UserNotice
from datetime import datetime, date, timedelta
import random
import io
import csv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from wtforms import BooleanField
# 初始化Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 用于session加密
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///police.db'  # 数据库路径
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化数据库和登录管理
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # 未登录时跳转的页面


# WTForms 用于用户管理表单
class UserForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=4, max=50)])
    name = StringField('真实姓名', validators=[DataRequired(), Length(min=2, max=50)])
    department = StringField('部门', validators=[DataRequired(), Length(min=2, max=50)])
    role = SelectField('角色', choices=[('admin', '管理员'), ('normal', '普通用户')], validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('提交')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('新密码', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('重置密码')

class CaseForm(FlaskForm):
    title = StringField('案件标题', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('案件描述', validators=[DataRequired()])
    status = SelectField('状态', choices=[('pending', '待审批'), ('approved', '已审批'), ('closed', '已结案')], validators=[DataRequired()])
    submit = SubmitField('提交')


class AnalyticsFilterForm(FlaskForm):
    department = SelectField('部门', choices=[], validators=[Optional()])
    time_range = SelectField('时间范围', choices=[('7', '近7天'), ('30', '近30天'), ('90', '近90天')], default='7')
    submit = SubmitField('筛选')

class DocumentForm(FlaskForm):
    title = StringField('文书标题', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('文书内容', validators=[DataRequired()])
    type = SelectField('文书类型', choices=[('criminal', '刑事'), ('public_security', '治安'), ('other', '其他')], validators=[DataRequired()])
    status = SelectField('状态', choices=[('draft', '草稿'), ('submitted', '已提交'), ('approved', '已审批')], validators=[DataRequired()])
    submit = SubmitField('提交')

# 消息表单
class MessageForm(FlaskForm):
    receiver = SelectField('接收人', validators=[DataRequired()])
    title = StringField('标题', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('内容', validators=[DataRequired()])
    submit = SubmitField('发送')

class SystemConfigForm(FlaskForm):
    log_level = SelectField('日志级别', choices=[('DEBUG', '调试'), ('INFO', '信息'), ('WARNING', '警告'), ('ERROR', '错误')], validators=[DataRequired()])
    max_upload_size = StringField('最大上传文件大小（MB）', validators=[DataRequired(), Length(min=1, max=10)])
    default_time_range = SelectField('默认时间范围', choices=[('7', '近7天'), ('30', '近30天'), ('90', '近90天')], validators=[DataRequired()])
    submit = SubmitField('保存配置')

class NoticeForm(FlaskForm):
    title = StringField('标题', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('内容', validators=[DataRequired()])
    department = StringField('部门', validators=[DataRequired(), Length(min=2, max=50)])
    is_urgent = BooleanField('紧急通知')
    submit = SubmitField('提交')
# 登录管理器回调：通过用户ID加载用户
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 初始化数据库
def init_db():
    try:
        db.create_all()
        print("数据库表创建成功")

        # 创建管理员用户
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', name='管理员', department='技术科', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            print("创建管理员用户: admin")

        # 创建测试普通用户
        if not User.query.filter_by(username='testuser').first():
            test_user = User(username='testuser', name='测试用户', department='刑侦科', role='normal')
            test_user.set_password('test123')
            db.session.add(test_user)
            print("创建测试用户: testuser")

        # 添加警情数据
        if not Incident.query.first():
            today = date.today()
            for i in range(90):  # 扩展到90天以支持时间范围筛选
                d = today - timedelta(days=i)
                db.session.add(Incident(type='criminal', count=random.randint(5, 10), date=d))
                db.session.add(Incident(type='public_security', count=random.randint(10, 20), date=d))
            print("添加测试警情数据")

        # 添加通知公告
        if not Notice.query.first():
            notices = [
                {
                    'title': '关于开展全市公安系统实战大练兵的通知',
                    'content': '为进一步提升公安队伍战斗力，决定开展全市公安系统实战大练兵活动...',
                    'department': '政治部',
                    'is_urgent': True
                },
                {
                    'title': '关于加强夏季治安防控工作的部署',
                    'content': '夏季来临，为确保社会面治安稳定，现将加强夏季治安防控工作有关事项通知如下...',
                    'department': '治安支队',
                    'is_urgent': False
                }
            ]
            for n in notices:
                db.session.add(Notice(title=n['title'], content=n['content'], department=n['department'],
                                      is_urgent=n['is_urgent']))
            print("添加测试通知公告")

        # 添加常用系统链接
        if not SystemLink.query.first():
            systems = [
                {'name': '警务信息综合平台', 'description': '人口、车辆信息查询', 'url': '#', 'icon': 'fa-database',
                 'color': 'text-primary'},
                {'name': '案件管理系统', 'description': '案件录入、审批、查询', 'url': '#', 'icon': 'fa-folder-open',
                 'color': 'text-green-600'}
            ]
            for s in systems:
                db.session.add(SystemLink(name=s['name'], description=s['description'], url=s['url'], icon=s['icon'],
                                          color=s['color']))
            print("添加测试系统链接")

        # 添加测试案件数据
        if not Case.query.first():
            test_user = User.query.filter_by(username='admin').first()
            if test_user:
                db.session.add(Case(
                    title='测试案件1',
                    description='这是一个测试案件，用于验证案件管理功能',
                    status='pending',
                    created_by=test_user.id
                ))
                db.session.add(Case(
                    title='测试案件2',
                    description='另一个测试案件，状态为已审批',
                    status='approved',
                    created_by=test_user.id
                ))
            test_user2 = User.query.filter_by(username='testuser').first()
            if test_user2:
                db.session.add(Case(
                    title='测试案件3',
                    description='测试用户创建的案件',
                    status='pending',
                    created_by=test_user2.id
                ))
            print("添加测试案件数据")

        # 添加测试文书数据
        if not Document.query.first():
            test_user = User.query.filter_by(username='admin').first()
            if test_user:
                db.session.add(Document(
                    title='测试调查报告',
                    content='这是一份测试调查报告，涉及刑事案件的调查记录...',
                    type='criminal',
                    status='draft',
                    created_by=test_user.id
                ))
                db.session.add(Document(
                    title='测试笔录',
                    content='这是一份测试笔录，记录治安案件的询问情况...',
                    type='public_security',
                    status='submitted',
                    created_by=test_user.id
                ))
            test_user2 = User.query.filter_by(username='testuser').first()
            if test_user2:
                db.session.add(Document(
                    title='测试其他文书',
                    content='这是一份由测试用户创建的其他类型文书...',
                    type='other',
                    status='draft',
                    created_by=test_user2.id
                ))
            print("添加测试文书数据")
        # 在现有init_db函数中添加测试消息

        if not Message.query.first():
            admin = User.query.filter_by(username='admin').first()
            test_user = User.query.filter_by(username='testuser').first()
            if admin and test_user:
                db.session.add(Message(
                    sender_id=admin.id,
                    receiver_id=test_user.id,
                    title='欢迎使用系统',
                    content='欢迎使用警务管理系统，如有任何问题请联系管理员。'
                ))
                db.session.add(Message(
                    sender_id=test_user.id,
                    receiver_id=admin.id,
                    title='测试消息',
                    content='这是一条测试消息，用于验证消息功能。'
                ))
            print("添加测试消息数据")

        if not SystemConfig.query.first():
            configs = [
                {'key': 'log_level', 'value': 'INFO', 'description': '系统日志级别'},
                {'key': 'max_upload_size', 'value': '10', 'description': '最大上传文件大小（MB）'},
                {'key': 'default_time_range', 'value': '7', 'description': '数据分析默认时间范围（天）'}
            ]
            for config in configs:
                db.session.add(SystemConfig(key=config['key'], value=config['value'], description=config['description']))
            print("添加测试系统配置数据")

        # 添加测试操作日志
        if not AuditLog.query.first():
            admin = User.query.filter_by(username='admin').first()
            if admin:
                db.session.add(AuditLog(user_id=admin.id, action='管理员初始化系统'))
            print("添加测试操作日志")

        db.session.commit()
        print("数据库初始化完成")
    except Exception as e:
        db.session.rollback()
        print(f"数据库初始化失败: {str(e)}")

import os

print("模板文件夹路径：", os.path.join(app.root_path, 'templates'))

# 应用启动时初始化数据库
with app.app_context():
    init_db()


# 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)  # 记录登录状态
            return redirect(url_for('index'))  # 登录成功跳转到首页
        return '用户名或密码错误'

    return render_template('login.html')


# 首页（需要登录才能访问）
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)


# 登出
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# 用户管理页面
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        return jsonify({'error': '无权限访问'}), 403
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        if User.query.filter_by(username=username).first():
            return render_template('admin_users.html', form=form, users=User.query.all(), error='用户名已存在')
        user = User(
            username=username,
            name=form.name.data,
            department=form.department.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('manage_users'))
    users = User.query.all()
    return render_template('admin_users.html', form=form, users=users)

# 编辑用户
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': '无权限访问'}), 403
    user = User.query.get_or_404(user_id)
    form = UserForm()
    if form.validate_on_submit():
        if form.username.data != user.username and User.query.filter_by(username=form.username.data).first():
            return render_template('edit_user.html', form=form, user=user, error='用户名已存在')
        user.username = form.username.data
        user.name = form.name.data
        user.department = form.department.data
        user.role = form.role.data
        if form.password.data:
            user.set_password(form.password.data)
        db.session.commit()
        return redirect(url_for('manage_users'))
    form.username.data = user.username
    form.name.data = user.name
    form.department.data = user.department
    form.role.data = user.role
    return render_template('edit_user.html', form=form, user=user)

# 删除用户
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': '无权限访问'}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'error': '不能删除自己'}), 403
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('manage_users'))

# 案件管理页面############################
@app.route('/cases', methods=['GET', 'POST'])
@login_required
def manage_cases():
    form = CaseForm()
    if form.validate_on_submit():
        case = Case(
            title=form.title.data,
            description=form.description.data,
            status=form.status.data,
            created_by=current_user.id
        )
        db.session.add(case)
        db.session.commit()
        flash(f'案件 {case.title} 创建成功', 'success')
        return redirect(url_for('manage_cases'))
    if current_user.role == 'admin':
        cases = Case.query.all()
    else:
        cases = Case.query.filter_by(created_by=current_user.id).all()
    return render_template('cases.html', form=form, cases=cases)

# 编辑案件
@app.route('/cases/edit/<int:case_id>', methods=['GET', 'POST'])
@login_required
def edit_case(case_id):
    case = Case.query.get_or_404(case_id)
    if current_user.role != 'admin' and case.created_by != current_user.id:
        flash('无权限编辑此案件', 'error')
        return redirect(url_for('manage_cases'))
    form = CaseForm()
    if form.validate_on_submit():
        case.title = form.title.data
        case.description = form.description.data
        case.status = form.status.data
        db.session.commit()
        flash(f'案件 {case.title} 更新成功', 'success')
        return redirect(url_for('manage_cases'))
    form.title.data = case.title
    form.description.data = case.description
    form.status.data = case.status
    return render_template('edit_case.html', form=form, case=case)

# 删除案件
@app.route('/cases/delete/<int:case_id>', methods=['POST'])
@login_required
def delete_case(case_id):
    case = Case.query.get_or_404(case_id)
    if current_user.role != 'admin' and case.created_by != current_user.id:
        flash('无权限删除此案件', 'error')
        return redirect(url_for('manage_cases'))
    db.session.delete(case)
    db.session.commit()
    flash(f'案件 {case.title} 已删除', 'success')
    return redirect(url_for('manage_cases'))
# 数据分析页面
@app.route('/analytics', methods=['GET', 'POST'])
@login_required
def analytics():
    form = AnalyticsFilterForm()
    # 修复 DISTINCT ON 问题，兼容 SQLite
    departments = db.session.query(User.department).distinct().all()
    form.department.choices = [('', '全部')] + [(d[0], d[0]) for d in departments]
    time_range = '7'
    department = None
    if form.validate_on_submit():
        time_range = form.time_range.data
        department = form.department.data if form.department.data else None
    return render_template('analytics.html', form=form, time_range=time_range, department=department)

# 数据分析统计接口
@app.route('/api/analytics-stats')
@login_required
def get_analytics_stats():
    try:
        time_range = request.args.get('time_range', '7')
        department = request.args.get('department')
        days = int(time_range)
        start_date = date.today() - timedelta(days=days - 1)

        # 警情趋势
        dates = [(date.today() - timedelta(days=i)).strftime('%m/%d') for i in range(days - 1, -1, -1)]
        criminal_data = []
        public_security_data = []
        for i in range(days):
            d = date.today() - timedelta(days=(days - 1 - i))
            criminal = Incident.query.filter_by(type='criminal', date=d).first()
            public = Incident.query.filter_by(type='public_security', date=d).first()
            criminal_data.append(criminal.count if criminal else 0)
            public_security_data.append(public.count if public else 0)

        # 案件状态分布
        query = Case.query.filter(Case.create_time >= datetime.combine(start_date, datetime.min.time()))
        if department and department != 'None' and (current_user.role != 'admin'):
            query = query.join(User, Case.created_by == User.id).filter(User.department == department)
        elif current_user.role != 'admin':
            query = query.join(User, Case.created_by == User.id).filter(User.department == current_user.department)
        elif department and department != 'None':
            query = query.join(User, Case.created_by == User.id).filter(User.department == department)
        status_counts = {
            'pending': query.filter(Case.status == 'pending').count(),
            'approved': query.filter(Case.status == 'approved').count(),
            'closed': query.filter(Case.status == 'closed').count()
        }

        # 部门案件数
        dept_counts = {}
        dept_query = Case.query.filter(Case.create_time >= datetime.combine(start_date, datetime.min.time()))
        if current_user.role != 'admin':
            dept_query = dept_query.join(User, Case.created_by == User.id).filter(User.department == current_user.department)
        elif department and department != 'None':
            dept_query = dept_query.join(User, Case.created_by == User.id).filter(User.department == department)
        for case in dept_query.all():
            if case.user:  # 确保 case 有关联的 user
                dept = case.user.department
                dept_counts[dept] = dept_counts.get(dept, 0) + 1

        return jsonify({
            'incident_trend': {
                'dates': dates,
                'criminal': criminal_data,
                'public_security': public_security_data
            },
            'case_status': status_counts,
            'department_cases': dept_counts
        })
    except Exception as e:
        print(f"API /api/analytics-stats 错误: {str(e)}")
        return jsonify({'error': str(e)}), 500
# 导出统计数据
@app.route('/api/export-analytics')
@login_required
def export_analytics():
    try:
        time_range = request.args.get('time_range', '7')
        department = request.args.get('department')
        days = int(time_range)
        start_date = date.today() - timedelta(days=days - 1)

        # 准备 CSV 数据
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['类型', '日期/状态/部门', '数量'])

        # 警情数据
        for i in range(days):
            d = date.today() - timedelta(days=(days - 1 - i))
            criminal = Incident.query.filter_by(type='criminal', date=d).first()
            public = Incident.query.filter_by(type='public_security', date=d).first()
            writer.writerow(['刑事警情', d.strftime('%Y-%m-%d'), criminal.count if criminal else 0])
            writer.writerow(['治安警情', d.strftime('%Y-%m-%d'), public.count if public else 0])

        # 案件状态
        query = Case.query.filter(Case.create_time >= datetime.combine(start_date, datetime.min.time()))
        if department and department != 'None' and (current_user.role != 'admin'):
            query = query.join(User, Case.created_by == User.id).filter(User.department == department)
        elif current_user.role != 'admin':
            query = query.join(User, Case.created_by == User.id).filter(User.department == current_user.department)
        elif department and department != 'None':
            query = query.join(User, Case.created_by == User.id).filter(User.department == department)
        writer.writerow(['案件状态', '待审批', query.filter(Case.status == 'pending').count()])
        writer.writerow(['案件状态', '已审批', query.filter(Case.status == 'approved').count()])
        writer.writerow(['案件状态', '已结案', query.filter(Case.status == 'closed').count()])

        # 部门案件数
        dept_query = Case.query.filter(Case.create_time >= datetime.combine(start_date, datetime.min.time()))
        if current_user.role != 'admin':
            dept_query = dept_query.join(User, Case.created_by == User.id).filter(User.department == current_user.department)
        elif department and department != 'None':
            dept_query = dept_query.join(User, Case.created_by == User.id).filter(User.department == department)
        dept_counts = {}
        for case in dept_query.all():
            if case.user:
                dept = case.user.department
                dept_counts[dept] = dept_counts.get(dept, 0) + 1
        for dept, count in dept_counts.items():
            writer.writerow(['部门案件', dept, count])

        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8-sig')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='analytics_export.csv'
        )
    except Exception as e:
        print(f"API /api/export-analytics 错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

# 接口1：获取警情统计数据（供图表使用）
@app.route('/api/incident-stats')
@login_required
def get_incident_stats():
    # 获取近7天的日期
    today = date.today()
    dates = [(today - timedelta(days=i)).strftime('%m/%d') for i in range(6, -1, -1)]

    # 查询刑事警情和治安警情数据
    criminal_data = []
    public_security_data = []

    for i in range(7):
        d = today - timedelta(days=(6 - i))  # 从7天前到今天
        criminal = Incident.query.filter_by(type='criminal', date=d).first()
        public = Incident.query.filter_by(type='public_security', date=d).first()

        criminal_data.append(criminal.count if criminal else 0)
        public_security_data.append(public.count if public else 0)

    return jsonify({
        'dates': dates,
        'criminal': criminal_data,
        'public_security': public_security_data
    })


# 接口2：获取通知公告列表
@app.route('/api/notices')
@login_required
def get_notices():
    notices = Notice.query.order_by(Notice.create_time.desc()).limit(3).all()
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'content': n.content[:50] + '...',  # 截取部分内容
        'department': n.department,
        'create_time': n.create_time.strftime('%Y-%m-%d'),
        'is_urgent': n.is_urgent
    } for n in notices])


# 接口3：获取今日统计数据（警情、案件等）
@app.route('/api/today-stats')
@login_required
def get_today_stats():
    today = date.today()
    # 今日警情总数（刑事+治安）
    criminal_today = Incident.query.filter_by(type='criminal', date=today).first()
    public_today = Incident.query.filter_by(type='public_security', date=today).first()
    total_incidents = (criminal_today.count if criminal_today else 0) + (public_today.count if public_today else 0)

    # 模拟其他统计数据（实际项目中应从数据库查询）
    return jsonify({
        'today_incidents': total_incidents,
        'handling_cases': 18,  # 在办案件
        'on_duty': 86,  # 今日出勤
        'pending_tasks': 7  # 待处理事项
    })


# 文书管理页面
@app.route('/documents', methods=['GET', 'POST'])
@login_required
def manage_documents():
    form = DocumentForm()
    if form.validate_on_submit():
        document = Document(
            title=form.title.data,
            content=form.content.data,
            type=form.type.data,
            status=form.status.data,
            created_by=current_user.id
        )
        db.session.add(document)
        db.session.commit()
        flash(f'文书 {document.title} 创建成功', 'success')
        return redirect(url_for('manage_documents'))
    if current_user.role == 'admin':
        documents = Document.query.all()
    else:
        documents = Document.query.filter_by(created_by=current_user.id).all()
    return render_template('documents.html', form=form, documents=documents)

# 编辑文书
@app.route('/documents/edit/<int:document_id>', methods=['GET', 'POST'])
@login_required
def edit_document(document_id):
    document = db.session.get(Document, document_id)
    if not document:
        flash('文书不存在', 'error')
        return redirect(url_for('manage_documents'))
    if current_user.role != 'admin' and document.created_by != current_user.id:
        flash('无权限编辑此文书', 'error')
        return redirect(url_for('manage_documents'))
    form = DocumentForm()
    if form.validate_on_submit():
        document.title = form.title.data
        document.content = form.content.data
        document.type = form.type.data
        document.status = form.status.data
        db.session.commit()
        flash(f'文书 {document.title} 更新成功', 'success')
        return redirect(url_for('manage_documents'))
    form.title.data = document.title
    form.content.data = document.content
    form.type.data = document.type
    form.status.data = document.status
    return render_template('edit_document.html', form=form, document=document)

# 删除文书
@app.route('/documents/delete/<int:document_id>', methods=['POST'])
@login_required
def delete_document(document_id):
    document = db.session.get(Document, document_id)
    if not document:
        flash('文书不存在', 'error')
        return redirect(url_for('manage_documents'))
    if current_user.role != 'admin' and document.created_by != current_user.id:
        flash('无权限删除此文书', 'error')
        return redirect(url_for('manage_documents'))
    db.session.delete(document)
    db.session.commit()
    flash(f'文书 {document.title} 已删除', 'success')
    return redirect(url_for('manage_documents'))

# 下载文书为 PDF
@app.route('/documents/download/<int:document_id>')
@login_required
def download_document(document_id):
    document = db.session.get(Document, document_id)
    if not document:
        flash('文书不存在', 'error')
        return redirect(url_for('manage_documents'))
    if current_user.role != 'admin' and document.created_by != current_user.id:
        flash('无权限下载此文书', 'error')
        return redirect(url_for('manage_documents'))

    # 创建 PDF
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    pdfmetrics.registerFont(TTFont('SimSun', 'SimSun.ttf'))  # 注册中文字体
    p.setFont('SimSun', 12)

    # 添加标题
    p.drawString(100, 750, f"文书标题: {document.title}")
    p.drawString(100, 730, f"类型: {'刑事' if document.type == 'criminal' else '治安' if document.type == 'public_security' else '其他'}")
    p.drawString(100, 710, f"状态: {'草稿' if document.status == 'draft' else '已提交' if document.status == 'submitted' else '已审批'}")
    p.drawString(100, 690, f"创建者: {document.user.name}")
    p.drawString(100, 670, f"创建时间: {document.create_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # 添加内容（简单分页处理）
    lines = document.content.split('\n')
    y = 650
    for line in lines:
        if y < 50:  # 新页面
            p.showPage()
            p.setFont('SimSun', 12)
            y = 750
        p.drawString(100, y, line[:80])  # 限制每行字符数
        y -= 20

    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"{document.title}.pdf"
    )


# 消息列表 - 收件箱
@app.route('/messages/inbox')
@login_required
def message_inbox():
    # 获取当前用户收到的消息，按时间倒序
    messages = Message.query.filter_by(receiver_id=current_user.id) \
        .order_by(Message.create_time.desc()).all()
    return render_template('messages/inbox.html', messages=messages)


# 消息列表 - 发件箱
@app.route('/messages/outbox')
@login_required
def message_outbox():
    # 获取当前用户发送的消息，按时间倒序
    messages = Message.query.filter_by(sender_id=current_user.id) \
        .order_by(Message.create_time.desc()).all()
    return render_template('messages/outbox.html', messages=messages)


# 发送消息
@app.route('/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    form = MessageForm()
    # 加载所有用户作为接收人选项
    users = User.query.filter(User.id != current_user.id).all()
    form.receiver.choices = [(str(user.id), user.name) for user in users]

    if form.validate_on_submit():
        message = Message(
            sender_id=current_user.id,
            receiver_id=int(form.receiver.data),
            title=form.title.data,
            content=form.content.data
        )
        db.session.add(message)
        db.session.commit()
        flash('消息发送成功', 'success')
        return redirect(url_for('message_outbox'))

    return render_template('messages/send.html', form=form)


# 查看消息详情
@app.route('/messages/<int:message_id>')
@login_required
def view_message(message_id):
    message = Message.query.get_or_404(message_id)
    # 验证权限：只能查看自己发送或接收的消息
    if message.receiver_id != current_user.id and message.sender_id != current_user.id:
        flash('无权访问此消息', 'error')
        return redirect(url_for('message_inbox'))

    # 如果是收件人查看，标记为已读
    if message.receiver_id == current_user.id and not message.is_read:
        message.is_read = True
        db.session.commit()

    return render_template('messages/detail.html', message=message)


# 删除消息
@app.route('/messages/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    # 验证权限
    if message.receiver_id != current_user.id and message.sender_id != current_user.id:
        flash('无权删除此消息', 'error')
        return redirect(url_for('message_inbox'))

    db.session.delete(message)
    db.session.commit()
    flash('消息已删除', 'success')
    # 根据消息类型返回对应的列表页
    if message.receiver_id == current_user.id:
        return redirect(url_for('message_inbox'))
    else:
        return redirect(url_for('message_outbox'))


# 获取未读消息数量（用于导航栏提示）
@app.route('/api/unread-count')
@login_required
def unread_count():
    count = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    return jsonify({'count': count})


# 系统配置页面
@app.route('/system-config', methods=['GET', 'POST'])
@login_required
def system_config():
    if current_user.role != 'admin':
        flash('无权限访问', 'error')
        return redirect(url_for('index'))
    form = SystemConfigForm()
    configs = {config.key: config for config in SystemConfig.query.all()}

    if form.validate_on_submit():
        updates = [
            {'key': 'log_level', 'value': form.log_level.data, 'description': '系统日志级别'},
            {'key': 'max_upload_size', 'value': form.max_upload_size.data, 'description': '最大上传文件大小（MB）'},
            {'key': 'default_time_range', 'value': form.default_time_range.data,
             'description': '数据分析默认时间范围（天）'}
        ]
        for update in updates:
            config = configs.get(update['key'])
            if config:
                config.value = update['value']
                config.last_updated = datetime.now()
            else:
                db.session.add(
                    SystemConfig(key=update['key'], value=update['value'], description=update['description']))
        db.session.add(AuditLog(user_id=current_user.id, action='更新系统配置'))
        db.session.commit()
        flash('系统配置更新成功', 'success')
        return redirect(url_for('system_config'))

    # 预填充表单
    form.log_level.data = configs.get('log_level', SystemConfig(value='INFO')).value
    form.max_upload_size.data = configs.get('max_upload_size', SystemConfig(value='10')).value
    form.default_time_range.data = configs.get('default_time_range', SystemConfig(value='7')).value

    # 获取最近10条操作日志
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('system_config.html', form=form, logs=logs)


from wtforms import BooleanField



# 消息通知页面
@app.route('/notices', methods=['GET', 'POST'])
@login_required
def manage_notices():
    form = NoticeForm()
    filter_urgent = request.args.get('filter_urgent', 'false') == 'true'

    # 创建通知（仅管理员）
    if form.validate_on_submit() and current_user.role == 'admin':
        notice = Notice(
            title=form.title.data,
            content=form.content.data,
            department=form.department.data,
            is_urgent=form.is_urgent.data
        )
        db.session.add(notice)
        db.session.add(AuditLog(user_id=current_user.id, action=f'创建通知 {notice.title}'))
        db.session.commit()
        flash('通知创建成功', 'success')
        return redirect(url_for('manage_notices'))

    # 查询通知
    query = Notice.query.order_by(Notice.create_time.desc())
    if filter_urgent:
        query = query.filter_by(is_urgent=True)
    notices = query.all()

    # 获取用户已读状态
    read_status = {un.notice_id: un.is_read for un in UserNotice.query.filter_by(user_id=current_user.id).all()}

    return render_template('notices.html', form=form, notices=notices, read_status=read_status,
                           filter_urgent=filter_urgent)


# 标记通知为已读
@app.route('/notices/mark-read/<int:notice_id>', methods=['POST'])
@login_required
def mark_notice_read(notice_id):
    notice = db.session.get(Notice, notice_id)
    if not notice:
        flash('通知不存在', 'error')
        return redirect(url_for('manage_notices'))
    user_notice = UserNotice.query.filter_by(user_id=current_user.id, notice_id=notice_id).first()
    if not user_notice:
        user_notice = UserNotice(user_id=current_user.id, notice_id=notice_id, is_read=True, read_time=datetime.now())
        db.session.add(user_notice)
    else:
        user_notice.is_read = True
        user_notice.read_time = datetime.now()
    db.session.add(AuditLog(user_id=current_user.id, action=f'标记通知 {notice.title} 为已读'))
    db.session.commit()
    flash('通知已标记为已读', 'success')
    return redirect(url_for('manage_notices'))


# 删除通知（仅管理员）
@app.route('/notices/delete/<int:notice_id>', methods=['POST'])
@login_required
def delete_notice(notice_id):
    if current_user.role != 'admin':
        flash('无权限删除通知', 'error')
        return redirect(url_for('manage_notices'))
    notice = db.session.get(Notice, notice_id)
    if not notice:
        flash('通知不存在', 'error')
        return redirect(url_for('manage_notices'))
    db.session.add(AuditLog(user_id=current_user.id, action=f'删除通知 {notice.title}'))
    db.session.delete(notice)
    db.session.commit()
    flash(f'通知 {notice.title} 已删除', 'success')
    return redirect(url_for('manage_notices'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)  # 内网可访问
