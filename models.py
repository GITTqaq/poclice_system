from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


# 用户模型（民警账号）
class User(UserMixin, db.Model):  # 继承UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)  # 登录账号
    password_hash = db.Column(db.String(128), nullable=False)  # 加密密码
    name = db.Column(db.String(50), nullable=False)  # 真实姓名
    department = db.Column(db.String(50), nullable=False)  # 所属部门
    role = db.Column(db.String(20), default="normal")  # 角色：admin/normal
    create_time = db.Column(db.DateTime, default=datetime.now)

    # 密码加密存储
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 密码验证
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 警情数据模型
class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)  # 类型：criminal（刑事）/public_security（治安）
    count = db.Column(db.Integer, nullable=False)  # 数量
    date = db.Column(db.Date, nullable=False)  # 日期
    create_time = db.Column(db.DateTime, default=datetime.now)


# 通知公告模型
class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)  # 标题
    content = db.Column(db.Text, nullable=False)  # 内容
    department = db.Column(db.String(50), nullable=False)  # 发布部门
    create_time = db.Column(db.DateTime, default=datetime.now)  # 发布时间
    is_urgent = db.Column(db.Boolean, default=False)  # 是否紧急


# 常用系统链接模型
class SystemLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)  # 系统名称
    description = db.Column(db.String(100))  # 描述
    url = db.Column(db.String(200), nullable=False)  # 链接地址
    icon = db.Column(db.String(50))  # 图标类名（Font Awesome）
    color = db.Column(db.String(20))  # 图标颜色样式
    create_time = db.Column(db.DateTime, default=datetime.now)

# 案件模型
class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # 状态：pending/approved/closed
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('User', backref='cases')

# 文书模型
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)  # 文书标题
    content = db.Column(db.Text, nullable=False)  # 文书内容
    type = db.Column(db.String(20), nullable=False)  # 文书类型：criminal/public_security/other
    status = db.Column(db.String(20), default='draft')  # 状态：draft/submitted/approved
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('User', backref='documents')


# 消息通知模型
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 发送者ID
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 接收者ID
    title = db.Column(db.String(100), nullable=False)  # 消息标题
    content = db.Column(db.Text, nullable=False)  # 消息内容
    is_read = db.Column(db.Boolean, default=False)  # 是否已读
    create_time = db.Column(db.DateTime, default=datetime.now)  # 发送时间

    # 关联用户表
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)  # 配置键（如 log_level）
    value = db.Column(db.String(100), nullable=False)  # 配置值
    description = db.Column(db.String(200))  # 配置描述
    last_updated = db.Column(db.DateTime, default=datetime.now)

# 操作日志模型
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # 操作描述
    timestamp = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('User', backref='audit_logs')

# 用户通知已读状态
class UserNotice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    notice_id = db.Column(db.Integer, db.ForeignKey('notice.id'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    read_time = db.Column(db.DateTime)
    user = db.relationship('User', backref='user_notices')
    notice = db.relationship('Notice', backref='user_notices')