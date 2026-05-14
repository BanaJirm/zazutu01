import os
import re
import uuid

try:
    from dotenv import load_dotenv
    _env_dir = os.path.dirname(os.path.abspath(__file__))
    _env_path = os.path.join(_env_dir, ".env")
    try:
        load_dotenv(encoding="utf-8")
        load_dotenv(_env_path, encoding="utf-8")
    except TypeError:

        load_dotenv()
        load_dotenv(_env_path)
except ImportError:
    pass

import hashlib
import secrets
import random
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    abort,
    current_app,
    session,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
    TextAreaField,
    FileField,
    SelectField,
    IntegerField,
)
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional
from sqlalchemy import or_, text, func
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    current_user,
    logout_user,
)


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    base_dir = os.path.abspath(os.path.dirname(__file__))
    instance_path = app.instance_path
    os.makedirs(instance_path, exist_ok=True)

    app.config.update(
        SECRET_KEY="change-this-secret-key",
        SQLALCHEMY_DATABASE_URI="sqlite:///"
        + os.path.join(instance_path, "app.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.path.join(base_dir, "static", "uploads"),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        ALLOWED_EXTENSIONS={"png", "jpg", "jpeg", "gif", "webp"},
        MAIL_SERVER=os.environ.get("MAIL_SERVER", "smtp.mail.ru"),
        MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
        MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "1") == "1",
        MAIL_USE_SSL=os.environ.get("MAIL_USE_SSL", "0") == "1",
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME", ""),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD", ""),
        MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER", ""),
        ADMIN_EMAIL=os.environ.get("ADMIN_EMAIL", ""),
    )

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    _env_exists = os.path.isfile(_env_path)
    print("[Почта] .env: %s (существует: %s)" % (_env_path, "да" if _env_exists else "нет"))
    _mail_server = app.config["MAIL_SERVER"] or ""
    _mail_user = app.config["MAIL_USERNAME"] or ""
    _mail_sender = app.config["MAIL_DEFAULT_SENDER"] or _mail_user
    _mail_has_pass = bool(app.config.get("MAIL_PASSWORD"))
    print("[Почта] MAIL_USERNAME=%r MAIL_PASSWORD=%s" % (_mail_user or "(пусто)", "задан" if _mail_has_pass else "не задан"))
    if _mail_server and _mail_sender and _mail_has_pass:
        print("[Почта] Настроена: сервер=%s, отправитель=%s" % (_mail_server, _mail_sender))
    else:
        print("[Почта] НЕ настроена: письма будут выводиться в консоль.")
        if not _mail_sender:
            print("  -> Задайте MAIL_USERNAME и MAIL_PASSWORD в .env (рядом с app.py или в папке запуска). См. EMAIL_SETUP.md")

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = "login"

    @app.context_processor
    def inject_chat_dates():

        today = datetime.utcnow().date()
        return {"today_date": today, "yesterday_date": today - timedelta(days=1)}

    register_models(app)
    register_routes(app)
    register_error_handlers(app)

    with app.app_context():
        db.create_all()
        _ensure_schema_compatibility()
        get_or_create_bot_user()

    return app


def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


_FILENAME_SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9_.-]")


def simple_secure_filename(filename: str) -> str:
    filename = os.path.basename(filename)
    if "." in filename:
        name_part, ext = filename.rsplit(".", 1)
        name_part = _FILENAME_SAFE_CHARS_RE.sub("_", name_part)
        ext = _FILENAME_SAFE_CHARS_RE.sub("", ext)
        return f"{name_part}.{ext}" if ext else name_part
    return _FILENAME_SAFE_CHARS_RE.sub("_", filename)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def check_password(password_hash: str, password: str) -> bool:
    try:
        salt, stored_digest = password_hash.split("$", 1)
    except ValueError:
        return False
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return digest == stored_digest


def generate_verification_code(length: int = 6) -> str:
    start = 10 ** (length - 1)
    end = 10**length - 1
    return str(random.randint(start, end))


def send_email(to_email: str, subject: str, body: str) -> None:

    app = current_app
    server = app.config.get("MAIL_SERVER") or ""
    username = app.config.get("MAIL_USERNAME") or ""
    password = app.config.get("MAIL_PASSWORD") or ""
    sender = app.config.get("MAIL_DEFAULT_SENDER") or username

    if not server or not sender or not password:
        print("=== Письмо НЕ отправлено (нет настроек почты) ===")
        print("  Задайте в .env: MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER. См. EMAIL_SETUP.md")
        print("To:", to_email)
        print("Subject:", subject)
        print(body)
        print("==================================================")
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email
    msg.set_content(body)

    use_ssl = app.config.get("MAIL_USE_SSL", False)
    use_tls = app.config.get("MAIL_USE_TLS", True)
    port = app.config.get("MAIL_PORT", 587)

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(server, port) as smtp:
                smtp.login(username, password)
                smtp.send_message(msg)
        elif use_tls:
            with smtplib.SMTP(server, port) as smtp:
                smtp.starttls()
                smtp.login(username, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(server, port) as smtp:
                smtp.login(username, password)
                smtp.send_message(msg)
    except Exception as e:
        print("[Почта] Ошибка отправки:", type(e).__name__, str(e))
        raise


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_code = db.Column(db.String(6), nullable=True)
    verification_code_created_at = db.Column(db.DateTime, nullable=True)
    avatar_filename = db.Column(db.String(255), nullable=True)

    boards = db.relationship("Board", backref="owner", lazy=True)
    pins = db.relationship("Pin", backref="author", lazy=True)
    comments = db.relationship("Comment", backref="author", lazy=True)
    likes = db.relationship("Like", backref="user", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = hash_password(password)

    def check_password(self, password: str) -> bool:
        return check_password(self.password_hash, password)


class Board(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    pins = db.relationship("Pin", backref="board", lazy=True, cascade="all, delete")


class Pin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=True, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    board_id = db.Column(db.Integer, db.ForeignKey("board.id"), nullable=False)

    comments = db.relationship(
        "Comment", backref="pin", lazy=True, cascade="all, delete"
    )
    likes = db.relationship("Like", backref="pin", lazy=True, cascade="all, delete")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    pin_id = db.Column(db.Integer, db.ForeignKey("pin.id"), nullable=False)


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    pin_id = db.Column(db.Integer, db.ForeignKey("pin.id"), nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "pin_id", name="unique_user_pin_like"),
    )


class FriendLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    accepted_at = db.Column(db.DateTime, nullable=True)

    user1_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    requested_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    status = db.Column(db.String(16), default="pending", nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user1_id", "user2_id", name="unique_friend_pair"),
    )

    def other_user_id(self, current_user_id: int) -> int:
        return self.user2_id if self.user1_id == current_user_id else self.user1_id


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    user1_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    __table_args__ = (
        db.UniqueConstraint("user1_id", "user2_id", name="unique_conversation_pair"),
    )

    def other_user_id(self, current_user_id: int) -> int:
        return self.user2_id if self.user1_id == current_user_id else self.user1_id


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    conversation_id = db.Column(
        db.Integer, db.ForeignKey("conversation.id"), nullable=False, index=True
    )
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(255), nullable=True)
    sticker_pack_id = db.Column(
        db.Integer, db.ForeignKey("sticker_pack.id"), nullable=True, index=True
    )
    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True, index=True)

    conversation = db.relationship(
        "Conversation", backref=db.backref("messages", lazy=True, cascade="all, delete")
    )
    sender = db.relationship("User", foreign_keys=[sender_id])
    sticker_pack = db.relationship("StickerPack", foreign_keys=[sticker_pack_id])
    reply_to = db.relationship("Message", remote_side=[id], foreign_keys=[reply_to_id])


class StickerPack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", backref=db.backref("sticker_packs", lazy=True))
    stickers = db.relationship(
        "Sticker", backref="pack", lazy=True, cascade="all, delete", order_by="Sticker.id"
    )


class Sticker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pack_id = db.Column(
        db.Integer, db.ForeignKey("sticker_pack.id"), nullable=False, index=True
    )
    image_filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class GroupChat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    avatar_filename = db.Column(db.String(255), nullable=True)

    owner = db.relationship("User", foreign_keys=[owner_id])


class GroupChatMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey("group_chat.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    role = db.Column(db.String(16), default="member", nullable=False)

    chat = db.relationship(
        "GroupChat", backref=db.backref("members", lazy=True, cascade="all, delete")
    )
    user = db.relationship("User", foreign_keys=[user_id])

    __table_args__ = (
        db.UniqueConstraint("chat_id", "user_id", name="unique_group_member"),
    )


class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    chat_id = db.Column(db.Integer, db.ForeignKey("group_chat.id"), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(255), nullable=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey("group_message.id"), nullable=True, index=True)

    chat = db.relationship(
        "GroupChat", backref=db.backref("messages", lazy=True, cascade="all, delete")
    )
    sender = db.relationship("User", foreign_keys=[sender_id])
    reply_to = db.relationship("GroupMessage", remote_side=[id], foreign_keys=[reply_to_id])


class RegisterForm(FlaskForm):
    username = StringField(
        "Имя пользователя",
        validators=[DataRequired(), Length(min=3, max=64)],
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Пароль",
        validators=[DataRequired(), Length(min=6)],
    )
    password2 = PasswordField(
        "Повторите пароль",
        validators=[DataRequired(), EqualTo("password", message="Пароли должны совпадать")],
    )
    submit = SubmitField("Зарегистрироваться")


class LoginForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Войти")


class BoardForm(FlaskForm):
    title = StringField("Название доски", validators=[DataRequired(), Length(max=120)])
    description = TextAreaField("Описание", validators=[Length(max=500)])
    submit = SubmitField("Создать доску")


class PinForm(FlaskForm):
    title = StringField("Заголовок", validators=[DataRequired(), Length(max=120)])
    description = TextAreaField("Описание", validators=[Length(max=1000)])
    board = SelectField("Доска", coerce=int, validators=[DataRequired()])
    image = FileField("Изображение", validators=[DataRequired()])
    submit = SubmitField("Добавить пин")


class CommentForm(FlaskForm):
    text = TextAreaField("Комментарий", validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField("Отправить")


class SearchForm(FlaskForm):
    query = StringField("Поиск по пинам", validators=[Length(max=120)])
    submit = SubmitField("Найти")


class ChatMessageForm(FlaskForm):
    body = TextAreaField("Сообщение", validators=[Length(max=4000)])
    image = FileField("Картинка")
    sticker_id = IntegerField("Стикер", validators=[Optional()])
    submit = SubmitField("Отправить")


class GroupChatCreateForm(FlaskForm):
    name = StringField(
        "Название группы",
        validators=[DataRequired(), Length(max=120)],
    )
    submit = SubmitField("Создать группу")


class StickerPackCreateForm(FlaskForm):
    name = StringField(
        "Название стикерпака",
        validators=[DataRequired(), Length(max=120)],
    )
    image = FileField("Первый стикер (изображение)", validators=[DataRequired()])
    submit = SubmitField("Создать стикерпак")


class StickerAddForm(FlaskForm):
    image = FileField("Изображение", validators=[DataRequired()])
    submit = SubmitField("Добавить стикер")


class ContactAdminForm(FlaskForm):
    subject = StringField("Тема", validators=[Length(max=200)])
    message = TextAreaField("Сообщение", validators=[DataRequired(), Length(max=2000)])
    submit = SubmitField("Отправить")


class ProfileForm(FlaskForm):
    username = StringField(
        "Имя пользователя",
        validators=[DataRequired(), Length(min=3, max=64)],
    )
    avatar = FileField("Аватарка")
    submit = SubmitField("Сохранить")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Текущий пароль", validators=[DataRequired()])
    new_password = PasswordField(
        "Новый пароль",
        validators=[DataRequired(), Length(min=6)],
    )
    new_password2 = PasswordField(
        "Повторите новый пароль",
        validators=[DataRequired(), EqualTo("new_password", message="Пароли должны совпадать")],
    )
    submit = SubmitField("Изменить пароль")


class ChangeEmailForm(FlaskForm):
    email = StringField("Новый email", validators=[DataRequired(), Email()])
    submit = SubmitField("Изменить email")


class CodeForm(FlaskForm):
    code = StringField(
        "Код из письма",
        validators=[DataRequired(), Length(min=6, max=6)],
    )
    submit = SubmitField("Подтвердить")


def _ensure_schema_compatibility() -> None:

    conn = db.engine.connect()
    try:

        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(user)"))}
        if "is_admin" not in cols:
            conn.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
        if "is_blocked" not in cols:
            conn.execute(
                text("ALTER TABLE user ADD COLUMN is_blocked BOOLEAN DEFAULT 0")
            )
        if "email_verified" not in cols:
            conn.execute(
                text(
                    "ALTER TABLE user ADD COLUMN email_verified BOOLEAN DEFAULT 0 NOT NULL"
                )
            )
        if "verification_code" not in cols:
            conn.execute(
                text("ALTER TABLE user ADD COLUMN verification_code VARCHAR(6)")
            )
        if "verification_code_created_at" not in cols:
            conn.execute(
                text("ALTER TABLE user ADD COLUMN verification_code_created_at DATETIME")
            )

        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(pin)"))}
        if "is_approved" not in cols:
            conn.execute(
                text("ALTER TABLE pin ADD COLUMN is_approved BOOLEAN DEFAULT 1")
            )

        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(message)"))}
        if cols and "image_filename" not in cols:
            conn.execute(
                text("ALTER TABLE message ADD COLUMN image_filename VARCHAR(255)")
            )
        if cols and "sticker_pack_id" not in cols:
            conn.execute(
                text("ALTER TABLE message ADD COLUMN sticker_pack_id INTEGER REFERENCES sticker_pack(id)")
            )
        if cols and "reply_to_id" not in cols:
            conn.execute(
                text("ALTER TABLE message ADD COLUMN reply_to_id INTEGER REFERENCES message(id)")
            )


        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(user)"))}
        if "avatar_filename" not in cols:
            conn.execute(
                text("ALTER TABLE user ADD COLUMN avatar_filename VARCHAR(255)")
            )

        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(group_chat)"))}
        if cols and "avatar_filename" not in cols:
            conn.execute(
                text("ALTER TABLE group_chat ADD COLUMN avatar_filename VARCHAR(255)")
            )

        existing_tables = {
            row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        }
        if "group_chat" not in existing_tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE group_chat (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(120) NOT NULL,
                        created_at DATETIME,
                        owner_id INTEGER NOT NULL
                    )
                    """
                )
            )
        if "group_chat_member" not in existing_tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE group_chat_member (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        chat_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        joined_at DATETIME,
                        role VARCHAR(16) DEFAULT 'member',
                        UNIQUE(chat_id, user_id)
                    )
                    """
                )
            )
        else:
            cols = {row[1] for row in conn.execute(text("PRAGMA table_info(group_chat_member)"))}
            if "role" not in cols:
                conn.execute(
                    text(
                        "ALTER TABLE group_chat_member ADD COLUMN role VARCHAR(16) DEFAULT 'member'"
                    )
                )
        if "group_message" not in existing_tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE group_message (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at DATETIME,
                        chat_id INTEGER NOT NULL,
                        sender_id INTEGER NOT NULL,
                        body TEXT,
                        image_filename VARCHAR(255)
                    )
                    """
                )
            )
        else:
            cols = {row[1] for row in conn.execute(text("PRAGMA table_info(group_message)"))}
            if "reply_to_id" not in cols:
                conn.execute(
                    text("ALTER TABLE group_message ADD COLUMN reply_to_id INTEGER REFERENCES group_message(id)")
                )
        if "sticker_pack" not in existing_tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE sticker_pack (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(120) NOT NULL,
                        user_id INTEGER NOT NULL,
                        created_at DATETIME
                    )
                    """
                )
            )
        if "sticker" not in existing_tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE sticker (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pack_id INTEGER NOT NULL,
                        image_filename VARCHAR(255) NOT NULL,
                        created_at DATETIME,
                        FOREIGN KEY (pack_id) REFERENCES sticker_pack(id)
                    )
                    """
                )
            )
    finally:
        conn.close()


BOT_USERNAME = "Zazutu Стикеры"

_ADD_TO_PACK_RE = re.compile(
    r"(?:добавить\s+в\s+стикерпак|в\s+стикерпак|добавить\s+в)\s*(\d+)", re.IGNORECASE
)
_DELETE_PACK_RE = re.compile(r"удалить\s+стикерпак\s*(\d+)", re.IGNORECASE)
_DELETE_STICKER_RE = re.compile(r"удалить\s+стикер\s*(\d+)", re.IGNORECASE)
_LIST_PACKS_RE = re.compile(r"^(?:мои\s+)?стикерпаки?$", re.IGNORECASE)


def _handle_bot_sticker_commands(
    user_id: int,
    conversation_id: int,
    bot_id: int,
    text_body: str,
    image_filename: str | None,
) -> None:
    """Обрабатывает команды стикер-бота: создание/удаление паков, добавление/удаление стикеров. Добавляет ответ бота в session."""
    text = (text_body or "").strip()
    text_lower = text.lower()


    m_pack = _DELETE_PACK_RE.search(text_lower)
    if m_pack and not image_filename:
        pack_id = int(m_pack.group(1))
        pack = StickerPack.query.get(pack_id)
        if not pack:
            _add_bot_message(conversation_id, bot_id, f"Стикерпак с id {pack_id} не найден.")
            return
        if pack.user_id != user_id:
            _add_bot_message(conversation_id, bot_id, "Редактировать стикерпак может только его создатель.")
            return
        name = pack.name
        Message.query.filter_by(sticker_pack_id=pack.id).update({Message.sticker_pack_id: None})
        db.session.delete(pack)
        _add_bot_message(conversation_id, bot_id, f"Стикерпак «{name}» удалён.")
        return


    m_sticker = _DELETE_STICKER_RE.search(text_lower)
    if m_sticker and not image_filename:
        sticker_id = int(m_sticker.group(1))
        sticker = Sticker.query.get(sticker_id)
        if not sticker:
            _add_bot_message(conversation_id, bot_id, f"Стикер с id {sticker_id} не найден.")
            return
        if sticker.pack.user_id != user_id:
            _add_bot_message(conversation_id, bot_id, "Удалять стикер может только создатель стикерпака.")
            return
        db.session.delete(sticker)
        _add_bot_message(conversation_id, bot_id, f"Стикер {sticker_id} удалён.")
        return

    if _LIST_PACKS_RE.match(text_lower) and not image_filename:
        packs = StickerPack.query.filter_by(user_id=user_id).order_by(StickerPack.id.desc()).all()
        if not packs:
            _add_bot_message(conversation_id, bot_id, "У вас пока нет стикерпаков. Отправьте фото, чтобы создать.")
            return
        lines = ["Ваши стикерпаки (команда: «в стикерпак N» — добавить фото в стикерпак):"]
        for p in packs:
            cnt = len(p.stickers)
            lines.append(f"  • id={p.id}: «{p.name}» — стикеров: {cnt}")
        _add_bot_message(conversation_id, bot_id, "\n".join(lines))
        return

    m_add = _ADD_TO_PACK_RE.search(text_lower)
    if m_add and image_filename:
        pack_id = int(m_add.group(1))
        pack = StickerPack.query.get(pack_id)
        if not pack:
            _add_bot_message(conversation_id, bot_id, f"Стикерпак с id {pack_id} не найден.")
            return
        if pack.user_id != user_id:
            _add_bot_message(conversation_id, bot_id, "Добавлять стикеры может только создатель стикерпака.")
            return
        sticker = Sticker(pack_id=pack.id, image_filename=image_filename)
        db.session.add(sticker)
        db.session.flush()
        cnt = Sticker.query.filter_by(pack_id=pack.id).count()
        _add_bot_message(conversation_id, bot_id, f"В стикерпак «{pack.name}» добавлен стикер. Всего стикеров: {cnt}.")
        return


    if image_filename:
        pack_name = text or ("Стикерпак от " + datetime.utcnow().strftime("%d.%m.%Y %H:%M"))
        pack = StickerPack(name=pack_name[:120], user_id=user_id)
        db.session.add(pack)
        db.session.flush()
        sticker = Sticker(pack_id=pack.id, image_filename=image_filename)
        db.session.add(sticker)
        _add_bot_message(
            conversation_id, bot_id,
            f"Стикерпак «{pack.name}» создан! Добавлен 1 стикер. Чтобы добавить ещё — отправьте фото с текстом «в стикерпак {pack.id}».",
            sticker_pack_id=pack.id,
        )
        return

    _add_bot_message(
        conversation_id,
        bot_id,
        "Управляйте стикерпаками через кнопки «Мои стикерпаки» и «Создать стикерпак» над чатом. Там можно создавать паки, добавлять и удалять стикеры.",
    )


def _add_bot_message(
    conversation_id: int, bot_id: int, body: str, sticker_pack_id: int | None = None
) -> None:
    msg = Message(
        conversation_id=conversation_id,
        sender_id=bot_id,
        body=body,
        sticker_pack_id=sticker_pack_id,
    )
    db.session.add(msg)


def get_or_create_bot_user() -> User:

    bot = User.query.filter_by(username=BOT_USERNAME).first()
    if bot:
        return bot
    bot = User(
        username=BOT_USERNAME,
        email="bot@zazutu.local",
        password_hash=hash_password(secrets.token_hex(32)),
        email_verified=True,
        is_blocked=False,
    )
    db.session.add(bot)
    db.session.commit()
    return bot


def register_models(app: Flask) -> None:
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


def save_image(file_storage, upload_folder: str) -> str:
    original_name = simple_secure_filename(file_storage.filename)
    ext = original_name.rsplit(".", 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    file_path = os.path.join(upload_folder, unique_name)
    file_storage.save(file_path)
    return unique_name


def register_routes(app: Flask) -> None:
    def _canonical_pair(a: int, b: int) -> tuple[int, int]:
        return (a, b) if a < b else (b, a)

    def _friend_link_between(user_a_id: int, user_b_id: int) -> FriendLink | None:
        x, y = _canonical_pair(user_a_id, user_b_id)
        return FriendLink.query.filter_by(user1_id=x, user2_id=y).first()

    def _are_friends(user_a_id: int, user_b_id: int) -> bool:
        link = _friend_link_between(user_a_id, user_b_id)
        return bool(link and link.status == "accepted")

    def _ensure_group_member(chat: GroupChat, user: User) -> bool:
        """Проверяет, является ли пользователь участником группы."""
        member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=user.id).first()
        return member is not None

    @app.route("/", methods=["GET", "POST"])
    def index():
        form = SearchForm()
        pins_query = Pin.query.filter_by(is_approved=True).order_by(func.random())

        if form.validate_on_submit():
            q = form.query.data or ""
            if q:
                like_pattern = f"%{q}%"
                pins_query = pins_query.filter(
                    or_(Pin.title.ilike(like_pattern), Pin.description.ilike(like_pattern))
                )

        pins = pins_query.all()
        return render_template("index.html", pins=pins, form=form)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        form = RegisterForm()
        if form.validate_on_submit():
            if User.query.filter(
                or_(User.username == form.username.data, User.email == form.email.data)
            ).first():
                flash("Пользователь с таким именем или email уже существует", "warning")
                return redirect(url_for("register"))

            code = generate_verification_code()
            session["pending_action"] = "register"
            session["pending_registration"] = {
                "username": form.username.data,
                "email": form.email.data,
                "password_hash": hash_password(form.password.data),
                "code": code,
                "code_created_at": datetime.utcnow().isoformat(),
            }

            try:
                send_email(
                    to_email=form.email.data,
                    subject="Подтверждение регистрации на Zazutu",
                    body=f"Ваш код для подтверждения регистрации: {code}",
                )
            except Exception as e:
                print("[Почта] Ошибка отправки при регистрации:", type(e).__name__, str(e))
                flash(
                    "Не удалось отправить письмо с кодом. "
                    "Если сайт на PythonAnywhere — на бесплатном аккаунте работает только Gmail: в .env укажите MAIL_SERVER=smtp.gmail.com и пароль приложения Google. См. PYTHONANYWHERE.md или EMAIL_SETUP.md.",
                    "danger",
                )
                return redirect(url_for("register"))

            flash(
                "Регистрация прошла успешно. Мы отправили код на вашу почту. "
                "Введите его, чтобы подтвердить аккаунт.",
                "success",
            )
            return redirect(url_for("verify_code"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if not user or not user.check_password(form.password.data):
                flash("Неверное имя пользователя или пароль", "danger")
                return render_template("login.html", form=form)

            if user.is_blocked:
                flash("Ваш аккаунт заблокирован. Обратитесь к администратору.", "danger")
                return render_template("login.html", form=form)

            code = generate_verification_code()
            user.verification_code = code
            user.verification_code_created_at = datetime.utcnow()
            db.session.commit()

            try:
                send_email(
                    to_email=user.email,
                    subject="Код входа на Zazutu",
                    body=f"Ваш код для входа: {code}",
                )
            except Exception as e:
                print("[Почта] Ошибка отправки при входе:", type(e).__name__, str(e))
                flash(
                    "Не удалось отправить письмо с кодом. "
                    "Если сайт на PythonAnywhere — используйте Gmail в .env (MAIL_SERVER=smtp.gmail.com, пароль приложения). См. PYTHONANYWHERE.md.",
                    "danger",
                )
                return render_template("login.html", form=form)

            session["pending_user_id"] = user.id
            session["pending_action"] = "login"
            flash("Мы отправили код на вашу почту. Введите его для входа.", "info")
            return redirect(url_for("verify_code"))
        return render_template("login.html", form=form)

    @app.route("/verify", methods=["GET", "POST"])
    def verify_code():
        action = session.get("pending_action")
        if not action:
            flash("Нет операции, требующей подтверждения кода.", "warning")
            return redirect(url_for("login"))

        user = None
        if action == "login":
            user_id = session.get("pending_user_id")
            if not user_id:
                flash("Нет операции входа, требующей кода.", "warning")
                return redirect(url_for("login"))
            user = User.query.get_or_404(int(user_id))
            if user.is_blocked:
                flash("Ваш аккаунт заблокирован. Обратитесь к администратору.", "danger")
                session.pop("pending_user_id", None)
                session.pop("pending_action", None)
                return redirect(url_for("login"))

        form = CodeForm()
        if form.validate_on_submit():
            code = form.code.data.strip()

            if action == "register":
                data = session.get("pending_registration") or {}
                stored_code = data.get("code")
                created_at_raw = data.get("code_created_at")
                if not stored_code or not created_at_raw:
                    flash("Код не найден. Попробуйте зарегистрироваться ещё раз.", "danger")
                else:
                    try:
                        created_at = datetime.fromisoformat(created_at_raw)
                    except Exception:
                        created_at = datetime.utcnow()
                    is_expired = datetime.utcnow() - created_at > timedelta(minutes=10)
                    if is_expired:
                        flash(
                            "Срок действия кода истёк. Попробуйте зарегистрироваться ещё раз.",
                            "danger",
                        )
                    elif code != stored_code:
                        flash("Неверный код.", "danger")
                    else:
                        user = User(
                            username=data["username"],
                            email=data["email"],
                        )
                        user.password_hash = data["password_hash"]
                        user.email_verified = True

                        if User.query.count() == 0:
                            user.is_admin = True

                        db.session.add(user)
                        db.session.commit()

                        session.pop("pending_registration", None)
                        session.pop("pending_action", None)

                        login_user(user)
                        flash("Email подтверждён. Вы вошли в аккаунт.", "success")
                        next_page = request.args.get("next")
                        return redirect(next_page or url_for("index"))
            elif action == "change_email":
                data = session.get("pending_email_change") or {}
                stored_code = data.get("code")
                created_at_raw = data.get("code_created_at")
                user_id = data.get("user_id")
                new_email = data.get("new_email")
                if not stored_code or not created_at_raw or not user_id or not new_email:
                    flash("Данные для изменения email не найдены. Попробуйте ещё раз.", "danger")
                else:
                    try:
                        created_at = datetime.fromisoformat(created_at_raw)
                    except Exception:
                        created_at = datetime.utcnow()
                    is_expired = datetime.utcnow() - created_at > timedelta(minutes=10)
                    if is_expired:
                        flash(
                            "Срок действия кода истёк. Попробуйте изменить email ещё раз.",
                            "danger",
                        )
                    elif code != stored_code:
                        flash("Неверный код.", "danger")
                    else:
                        u = User.query.get(int(user_id))
                        if not u:
                            flash("Пользователь не найден.", "danger")
                        else:
                            u.email = new_email
                            u.email_verified = True
                            db.session.commit()

                            session.pop("pending_email_change", None)
                            session.pop("pending_action", None)

                            flash("Email успешно изменён.", "success")
                            return redirect(url_for("profile"))
            else:
                if not user or not user.verification_code or not user.verification_code_created_at:
                    flash("Код не найден. Попробуйте войти ещё раз.", "danger")
                else:
                    is_expired = (
                        datetime.utcnow() - user.verification_code_created_at
                        > timedelta(minutes=10)
                    )
                    if is_expired:
                        flash(
                            "Срок действия кода истёк. Попробуйте войти ещё раз.",
                            "danger",
                        )
                    elif code != user.verification_code:
                        flash("Неверный код.", "danger")
                    else:
                        user.email_verified = True
                        user.verification_code = None
                        user.verification_code_created_at = None
                        db.session.commit()

                        session.pop("pending_user_id", None)
                        session.pop("pending_action", None)

                        login_user(user)
                        flash("Вы успешно вошли.", "success")
                        next_page = request.args.get("next")
                        return redirect(next_page or url_for("index"))

        return render_template("verify_code.html", form=form, action=action)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Вы вышли из аккаунта.", "info")
        return redirect(url_for("index"))

    @app.route("/boards/create", methods=["GET", "POST"])
    @login_required
    def create_board():
        form = BoardForm()
        if form.validate_on_submit():
            board = Board(
                title=form.title.data,
                description=form.description.data,
                owner=current_user,
            )
            db.session.add(board)
            db.session.commit()
            flash("Доска создана.", "success")
            return redirect(url_for("board_detail", board_id=board.id))
        return render_template("create_board.html", form=form)

    @app.route("/boards/<int:board_id>")
    def board_detail(board_id: int):
        board = Board.query.get_or_404(board_id)
        visible_pins = [p for p in board.pins if p.is_approved]
        return render_template("board_detail.html", board=board, pins=visible_pins)

    @app.route("/boards/<int:board_id>/delete", methods=["POST"])
    @login_required
    def board_delete(board_id: int):
        board = Board.query.get_or_404(board_id)
        if board.user_id != current_user.id:
            abort(403)
        db.session.delete(board)
        db.session.commit()
        flash("Доска удалена.", "success")
        return redirect(url_for("index"))

    @app.route("/pins/create", methods=["GET", "POST"])
    @login_required
    def create_pin():
        form = PinForm()
        form.board.choices = [
            (b.id, b.title) for b in Board.query.filter_by(owner=current_user).all()
        ]
        if not form.board.choices:
            flash("Сначала создайте хотя бы одну доску.", "warning")
            return redirect(url_for("create_board"))

        if form.validate_on_submit():
            file = form.image.data
            if not file or file.filename == "":
                flash("Выберите файл изображения.", "danger")
                return redirect(request.url)

            filename = file.filename
            if "." not in filename:
                flash("Неверный формат файла.", "danger")
                return redirect(request.url)

            ext = filename.rsplit(".", 1)[1].lower()
            if ext not in app.config["ALLOWED_EXTENSIONS"]:
                flash("Разрешены только изображения (png, jpg, jpeg, gif, webp).", "danger")
                return redirect(request.url)

            saved_name = save_image(file, app.config["UPLOAD_FOLDER"])
            pin = Pin(
                title=form.title.data,
                description=form.description.data,
                image_filename=saved_name,
                author=current_user,
                board_id=form.board.data,
                is_approved=True,
            )
            db.session.add(pin)
            db.session.commit()
            flash("Пин добавлен.", "success")
            return redirect(url_for("pin_detail", pin_id=pin.id))

        return render_template("create_pin.html", form=form)

    @app.route("/pins/<int:pin_id>", methods=["GET", "POST"])
    def pin_detail(pin_id: int):
        pin = Pin.query.get_or_404(pin_id)
        if not pin.is_approved and not (
            current_user.is_authenticated and current_user.is_admin
        ):
            abort(404)
        form = CommentForm()
        if form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("Необходимо войти, чтобы комментировать.", "warning")
                return redirect(url_for("login"))
            comment = Comment(
                text=form.text.data,
                author=current_user,
                pin=pin,
            )
            db.session.add(comment)
            db.session.commit()
            flash("Комментарий добавлен.", "success")
            return redirect(url_for("pin_detail", pin_id=pin.id))

        is_liked = False
        if current_user.is_authenticated:
            is_liked = (
                Like.query.filter_by(user_id=current_user.id, pin_id=pin.id).first()
                is not None
            )

        return render_template(
            "pin_detail.html",
            pin=pin,
            form=form,
            is_liked=is_liked,
        )

    @app.route("/pins/<int:pin_id>/comments/<int:comment_id>/delete", methods=["POST"])
    @login_required
    def comment_delete(pin_id: int, comment_id: int):
        pin = Pin.query.get_or_404(pin_id)
        comment = Comment.query.filter_by(id=comment_id, pin_id=pin.id).first_or_404()
        if comment.user_id != current_user.id and not current_user.is_admin:
            abort(403)
        db.session.delete(comment)
        db.session.commit()
        flash("Комментарий удалён.", "success")
        return redirect(url_for("pin_detail", pin_id=pin.id))

    @app.route("/admin/pins")
    @login_required
    def admin_pins():
        if not current_user.is_admin:
            abort(403)
        pins = Pin.query.order_by(Pin.created_at.desc()).all()
        return render_template("admin_pins.html", pins=pins)

    @app.route("/admin/pins/<int:pin_id>/approve", methods=["POST"])
    @login_required
    def admin_approve_pin(pin_id: int):
        if not current_user.is_admin:
            abort(403)
        pin = Pin.query.get_or_404(pin_id)
        pin.is_approved = True
        db.session.commit()
        flash("Пин одобрен и показывается в ленте.", "success")
        return redirect(url_for("admin_pins"))

    @app.route("/admin/pins/<int:pin_id>/hide", methods=["POST"])
    @login_required
    def admin_hide_pin(pin_id: int):
        if not current_user.is_admin:
            abort(403)
        pin = Pin.query.get_or_404(pin_id)
        pin.is_approved = False
        db.session.commit()
        flash("Пин скрыт из ленты.", "info")
        return redirect(url_for("admin_pins"))

    @app.route("/admin/pins/<int:pin_id>/delete", methods=["POST"])
    @login_required
    def admin_delete_pin(pin_id: int):
        if not current_user.is_admin:
            abort(403)
        pin = Pin.query.get_or_404(pin_id)
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], pin.image_filename)
        db.session.delete(pin)
        db.session.commit()
        if os.path.exists(image_path):
            try:
                os.remove(image_path)
            except OSError:
                pass
        flash("Пин удалён.", "info")
        return redirect(url_for("admin_pins"))

    @app.route("/pins/<int:pin_id>/like", methods=["POST"])
    @login_required
    def like_pin(pin_id: int):
        pin = Pin.query.get_or_404(pin_id)
        existing = Like.query.filter_by(user_id=current_user.id, pin_id=pin.id).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()
            flash("Лайк удалён.", "info")
        else:
            like = Like(user=current_user, pin=pin)
            db.session.add(like)
            try:
                db.session.commit()
                flash("Пин понравился.", "success")
            except Exception:
                db.session.rollback()
                flash("Не удалось поставить лайк.", "danger")
        return redirect(url_for("pin_detail", pin_id=pin.id))

    @app.route("/profile")
    @login_required
    def profile():
        user = current_user
        return render_template("profile.html", user=user)

    @app.route("/settings/profile", methods=["GET", "POST"])
    @login_required
    def settings_profile():
        form = ProfileForm(obj=current_user)
        if form.validate_on_submit():
            new_username = form.username.data.strip()
            if new_username != current_user.username:
                exists = User.query.filter(
                    User.username == new_username, User.id != current_user.id
                ).first()
                if exists:
                    flash("Пользователь с таким именем уже существует.", "danger")
                    return render_template("settings_profile.html", form=form)
                current_user.username = new_username

            file = form.avatar.data
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash(
                        "Разрешены только изображения (png, jpg, jpeg, gif, webp).",
                        "danger",
                    )
                    return render_template("settings_profile.html", form=form)
                filename = save_image(file, current_app.config["UPLOAD_FOLDER"])
                current_user.avatar_filename = filename

            db.session.commit()
            flash("Профиль обновлён.", "success")
            return redirect(url_for("profile"))

        return render_template("settings_profile.html", form=form)

    @app.route("/settings/password", methods=["GET", "POST"])
    @login_required
    def settings_password():
        form = ChangePasswordForm()
        if form.validate_on_submit():
            if not current_user.check_password(form.current_password.data):
                flash("Текущий пароль введён неверно.", "danger")
                return render_template("settings_password.html", form=form)

            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash("Пароль изменён.", "success")
            return redirect(url_for("profile"))
        return render_template("settings_password.html", form=form)

    @app.route("/settings/email", methods=["GET", "POST"])
    @login_required
    def settings_email():
        form = ChangeEmailForm()
        if form.validate_on_submit():
            new_email = form.email.data.strip().lower()
            if new_email == current_user.email:
                flash("Этот email уже привязан к вашему аккаунту.", "info")
                return render_template("settings_email.html", form=form)

            exists = User.query.filter(
                User.email == new_email, User.id != current_user.id
            ).first()
            if exists:
                flash("Пользователь с таким email уже существует.", "danger")
                return render_template("settings_email.html", form=form)

            code = generate_verification_code()
            session["pending_action"] = "change_email"
            session["pending_email_change"] = {
                "user_id": current_user.id,
                "new_email": new_email,
                "code": code,
                "code_created_at": datetime.utcnow().isoformat(),
            }

            try:
                send_email(
                    to_email=new_email,
                    subject="Подтверждение изменения email на Zazutu",
                    body=f"Ваш код для изменения email: {code}",
                )
            except Exception as e:
                print("[Почта] Ошибка отправки при смене email:", type(e).__name__, str(e))
                flash(
                    "Не удалось отправить письмо с кодом. "
                    "Если сайт на PythonAnywhere — используйте Gmail в .env. См. PYTHONANYWHERE.md.",
                    "danger",
                )
                return render_template("settings_email.html", form=form)

            flash(
                "Мы отправили код подтверждения на новый email. Введите его, чтобы завершить изменение.",
                "info",
            )
            return redirect(url_for("verify_code"))
        return render_template("settings_email.html", form=form)

    @app.route("/admin/users")
    @login_required
    def admin_users():
        if not current_user.is_admin:
            abort(403)
        q = (request.args.get("q") or "").strip()
        users_query = User.query
        if q:
            like_pattern = f"%{q}%"
            users_query = users_query.filter(User.username.ilike(like_pattern))
        users = users_query.order_by(User.created_at.desc()).all()
        return render_template("admin_users.html", users=users, q=q)

    @app.route("/admin/users/<int:user_id>/block", methods=["POST"])
    @login_required
    def admin_block_user(user_id: int):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash("Нельзя блокировать самого себя.", "warning")
            return redirect(url_for("admin_users"))
        user.is_blocked = True
        db.session.commit()
        flash(f"Пользователь {user.username} заблокирован.", "info")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/unblock", methods=["POST"])
    @login_required
    def admin_unblock_user(user_id: int):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(user_id)
        user.is_blocked = False
        db.session.commit()
        flash(f"Пользователь {user.username} разблокирован.", "info")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    def admin_delete_user(user_id: int):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash("Нельзя удалить самого себя.", "warning")
            return redirect(url_for("admin_users"))
        if user.username == BOT_USERNAME:
            flash("Нельзя удалить бота.", "warning")
            return redirect(url_for("admin_users"))

        for board in list(user.boards):
            db.session.delete(board)
        GroupMessage.query.filter_by(sender_id=user.id).delete()
        for chat in GroupChat.query.filter_by(owner_id=user.id).all():
            db.session.delete(chat)
        GroupChatMember.query.filter_by(user_id=user.id).delete()
        for conv in Conversation.query.filter(
            or_(Conversation.user1_id == user.id, Conversation.user2_id == user.id)
        ).all():
            db.session.delete(conv)
        FriendLink.query.filter(
            or_(FriendLink.user1_id == user.id, FriendLink.user2_id == user.id)
        ).delete()
        Comment.query.filter_by(user_id=user.id).delete()
        Like.query.filter_by(user_id=user.id).delete()
        Pin.query.filter_by(user_id=user.id).delete()
        for pack in list(StickerPack.query.filter_by(user_id=user.id).all()):
            db.session.delete(pack)

        db.session.delete(user)
        db.session.commit()
        flash("Пользователь удалён.", "info")
        return redirect(url_for("admin_users"))

    @app.route("/friends")
    @login_required
    def friends():
        q = (request.args.get("q") or "").strip()

        my_links = FriendLink.query.filter(
            or_(FriendLink.user1_id == current_user.id, FriendLink.user2_id == current_user.id)
        ).order_by(FriendLink.created_at.desc()).all()

        incoming = [
            l
            for l in my_links
            if l.status == "pending" and l.requested_by_id != current_user.id
        ]
        outgoing = [
            l
            for l in my_links
            if l.status == "pending" and l.requested_by_id == current_user.id
        ]
        accepted = [l for l in my_links if l.status == "accepted"]

        user_ids_needed = set()
        for l in my_links:
            user_ids_needed.add(l.user1_id)
            user_ids_needed.add(l.user2_id)
            user_ids_needed.add(l.requested_by_id)
        users_map = {u.id: u for u in User.query.filter(User.id.in_(user_ids_needed)).all()} if user_ids_needed else {}

        search_results = []
        relationship_by_user_id: dict[int, FriendLink] = {}
        if q:
            like_pattern = f"%{q}%"
            search_results = (
                User.query.filter(User.id != current_user.id)
                .filter(User.is_blocked == False)  # noqa: E712
                .filter(User.username.ilike(like_pattern))
                .order_by(User.username.asc())
                .limit(50)
                .all()
            )
            for l in my_links:
                other_id = l.other_user_id(current_user.id)
                relationship_by_user_id[other_id] = l

        return render_template(
            "friends.html",
            q=q,
            incoming=incoming,
            outgoing=outgoing,
            friends_links=accepted,
            users_map=users_map,
            search_results=search_results,
            relationship_by_user_id=relationship_by_user_id,
        )

    @app.route("/friends/request/<int:user_id>", methods=["POST"])
    @login_required
    def friend_request(user_id: int):
        if user_id == current_user.id:
            abort(400)
        other = User.query.get_or_404(user_id)
        if other.is_blocked:
            abort(404)
        existing = _friend_link_between(current_user.id, other.id)
        if existing:
            flash("Связь уже существует (заявка или дружба).", "info")
            return redirect(url_for("friends", q=request.args.get("q", "")))

        x, y = _canonical_pair(current_user.id, other.id)
        link = FriendLink(
            user1_id=x,
            user2_id=y,
            requested_by_id=current_user.id,
            status="pending",
        )
        db.session.add(link)
        db.session.commit()
        flash(f"Заявка в друзья отправлена пользователю {other.username}.", "success")
        return redirect(url_for("friends", q=request.args.get("q", "")))

    @app.route("/friends/accept/<int:link_id>", methods=["POST"])
    @login_required
    def friend_accept(link_id: int):
        link = FriendLink.query.get_or_404(link_id)
        if current_user.id not in (link.user1_id, link.user2_id):
            abort(403)
        if link.status != "pending":
            flash("Эту заявку нельзя принять.", "warning")
            return redirect(url_for("friends"))
        if link.requested_by_id == current_user.id:
            abort(403)
        link.status = "accepted"
        link.accepted_at = datetime.utcnow()
        db.session.commit()
        flash("Заявка принята. Теперь вы друзья.", "success")
        return redirect(url_for("friends"))

    @app.route("/friends/decline/<int:link_id>", methods=["POST"])
    @login_required
    def friend_decline(link_id: int):
        link = FriendLink.query.get_or_404(link_id)
        if current_user.id not in (link.user1_id, link.user2_id):
            abort(403)
        if link.status != "pending":
            flash("Эту заявку нельзя отклонить.", "warning")
            return redirect(url_for("friends"))
        if link.requested_by_id == current_user.id:
            abort(403)
        db.session.delete(link)
        db.session.commit()
        flash("Заявка отклонена.", "info")
        return redirect(url_for("friends"))

    @app.route("/friends/cancel/<int:link_id>", methods=["POST"])
    @login_required
    def friend_cancel(link_id: int):
        link = FriendLink.query.get_or_404(link_id)
        if current_user.id not in (link.user1_id, link.user2_id):
            abort(403)
        if link.status != "pending":
            flash("Эту заявку нельзя отменить.", "warning")
            return redirect(url_for("friends"))
        if link.requested_by_id != current_user.id:
            abort(403)
        db.session.delete(link)
        db.session.commit()
        flash("Заявка отменена.", "info")
        return redirect(url_for("friends"))

    @app.route("/friends/remove/<int:link_id>", methods=["POST"])
    @login_required
    def friend_remove(link_id: int):
        link = FriendLink.query.get_or_404(link_id)
        if current_user.id not in (link.user1_id, link.user2_id):
            abort(403)
        if link.status != "accepted":
            flash("Это не дружба.", "warning")
            return redirect(url_for("friends"))
        db.session.delete(link)
        db.session.commit()
        flash("Пользователь удалён из друзей.", "info")
        return redirect(url_for("friends"))

    @app.route("/chats")
    @login_required
    def chats():
        conversations = (
            Conversation.query.filter(
                or_(
                    Conversation.user1_id == current_user.id,
                    Conversation.user2_id == current_user.id,
                )
            )
            .order_by(Conversation.updated_at.desc())
            .all()
        )

        user_ids = set()
        for c in conversations:
            user_ids.add(c.user1_id)
            user_ids.add(c.user2_id)
        users_map = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}

        last_message_by_conversation_id: dict[int, Message] = {}
        if conversations:
            conv_ids = [c.id for c in conversations]
            last_messages = (
                Message.query.filter(Message.conversation_id.in_(conv_ids))
                .order_by(Message.created_at.desc())
                .all()
            )
            seen = set()
            for m in last_messages:
                if m.conversation_id in seen:
                    continue
                last_message_by_conversation_id[m.conversation_id] = m
                seen.add(m.conversation_id)
                if len(seen) == len(conv_ids):
                    break

        bot = get_or_create_bot_user()
        x, y = _canonical_pair(current_user.id, bot.id)
        bot_conv = Conversation.query.filter_by(user1_id=x, user2_id=y).first()
        bot_conv_id = bot_conv.id if bot_conv else None
        conversations = [c for c in conversations if c.id != bot_conv_id]

        return render_template(
            "chats.html",
            conversations=conversations,
            users_map=users_map,
            last_message_by_conversation_id=last_message_by_conversation_id,
            bot_user=bot,
            bot_conversation=bot_conv,
        )

    @app.route("/chats/start_bot", methods=["POST"])
    @login_required
    def chats_start_bot():
        bot = get_or_create_bot_user()
        x, y = _canonical_pair(current_user.id, bot.id)
        conv = Conversation.query.filter_by(user1_id=x, user2_id=y).first()
        if not conv:
            conv = Conversation(user1_id=x, user2_id=y)
            db.session.add(conv)
            db.session.commit()
        return redirect(url_for("chat_detail", conversation_id=conv.id))

    @app.route("/chats/start/<int:user_id>", methods=["POST"])
    @login_required
    def chats_start(user_id: int):
        if user_id == current_user.id:
            abort(400)
        bot = get_or_create_bot_user()
        if user_id == bot.id:
            x, y = _canonical_pair(current_user.id, bot.id)
            conv = Conversation.query.filter_by(user1_id=x, user2_id=y).first()
            if not conv:
                conv = Conversation(user1_id=x, user2_id=y)
                db.session.add(conv)
                db.session.commit()
            return redirect(url_for("chat_detail", conversation_id=conv.id))

        other = User.query.get_or_404(user_id)
        if other.is_blocked:
            abort(404)
        if not _are_friends(current_user.id, other.id):
            flash("Чат доступен только для друзей.", "warning")
            return redirect(url_for("friends"))

        x, y = _canonical_pair(current_user.id, other.id)
        conv = Conversation.query.filter_by(user1_id=x, user2_id=y).first()
        if not conv:
            conv = Conversation(user1_id=x, user2_id=y)
            db.session.add(conv)
            db.session.commit()
        return redirect(url_for("chat_detail", conversation_id=conv.id))

    @app.route("/sticker_packs")
    @login_required
    def sticker_packs_list():
        packs = (
            StickerPack.query.filter_by(user_id=current_user.id)
            .order_by(StickerPack.created_at.desc())
            .all()
        )
        return render_template("sticker_packs.html", packs=packs)

    @app.route("/sticker_packs/create", methods=["GET", "POST"])
    @login_required
    def sticker_pack_create():
        form = StickerPackCreateForm()
        if form.validate_on_submit():
            if not allowed_file(form.image.data.filename):
                flash("Разрешены только изображения (png, jpg, jpeg, gif, webp).", "danger")
                return render_template("sticker_pack_create.html", form=form)
            image_filename = save_image(form.image.data, app.config["UPLOAD_FOLDER"])
            pack = StickerPack(
                name=form.name.data.strip()[:120],
                user_id=current_user.id,
            )
            db.session.add(pack)
            db.session.flush()
            sticker = Sticker(pack_id=pack.id, image_filename=image_filename)
            db.session.add(sticker)
            db.session.commit()
            flash("Стикерпак создан.", "success")
            return redirect(url_for("sticker_pack_detail", pack_id=pack.id))
        return render_template("sticker_pack_create.html", form=form)

    @app.route("/sticker_packs/<int:pack_id>", methods=["GET", "POST"])
    @login_required
    def sticker_pack_detail(pack_id: int):
        pack = StickerPack.query.get_or_404(pack_id)
        if pack.user_id != current_user.id:
            abort(403)
        form = StickerAddForm()
        if form.validate_on_submit():
            if not allowed_file(form.image.data.filename):
                flash("Разрешены только изображения (png, jpg, jpeg, gif, webp).", "danger")
                return redirect(url_for("sticker_pack_detail", pack_id=pack.id))
            image_filename = save_image(form.image.data, app.config["UPLOAD_FOLDER"])
            sticker = Sticker(pack_id=pack.id, image_filename=image_filename)
            db.session.add(sticker)
            db.session.commit()
            flash("Стикер добавлен.", "success")
            return redirect(url_for("sticker_pack_detail", pack_id=pack.id))
        return render_template("sticker_pack_detail.html", pack=pack, form=form)

    @app.route("/sticker_packs/<int:pack_id>/delete", methods=["POST"])
    @login_required
    def sticker_pack_delete(pack_id: int):
        pack = StickerPack.query.get_or_404(pack_id)
        if pack.user_id != current_user.id:
            abort(403)
        Message.query.filter_by(sticker_pack_id=pack.id).update({Message.sticker_pack_id: None})
        db.session.delete(pack)
        db.session.commit()
        flash("Стикерпак удалён.", "info")
        return redirect(url_for("sticker_packs_list"))

    @app.route("/sticker_packs/<int:pack_id>/stickers/<int:sticker_id>/delete", methods=["POST"])
    @login_required
    def sticker_delete(pack_id: int, sticker_id: int):
        pack = StickerPack.query.get_or_404(pack_id)
        if pack.user_id != current_user.id:
            abort(403)
        sticker = Sticker.query.filter_by(id=sticker_id, pack_id=pack_id).first_or_404()
        db.session.delete(sticker)
        db.session.commit()
        flash("Стикер удалён.", "info")
        return redirect(url_for("sticker_pack_detail", pack_id=pack_id))

    @app.route("/contact", methods=["GET", "POST"])
    @login_required
    def contact_admin():
        admin_email = app.config.get("ADMIN_EMAIL") or ""
        if not admin_email:
            admin = User.query.filter_by(is_admin=True).first()
            if admin:
                admin_email = admin.email
        form = ContactAdminForm()
        if form.validate_on_submit():
            if not admin_email:
                flash("Администратор не настроен. Обратитесь к владельцу сайта.", "warning")
                return redirect(url_for("contact_admin"))
            subject = (form.subject.data or "").strip() or "Сообщение с сайта Zazutu"
            body = (
                f"От: {current_user.username} ({current_user.email})\n\n"
                f"{form.message.data}"
            )
            try:
                send_email(admin_email, f"[Zazutu] {subject}", body)
                flash("Сообщение отправлено администратору.", "success")
                return redirect(url_for("index"))
            except Exception:
                flash("Не удалось отправить сообщение. Попробуйте позже.", "danger")
        return render_template(
            "contact_admin.html",
            form=form,
            has_admin=bool(admin_email),
        )

    @app.route("/group_chats", methods=["GET", "POST"])
    @login_required
    def group_chats():
        form = GroupChatCreateForm()
        if form.validate_on_submit():
            chat = GroupChat(name=form.name.data.strip(), owner_id=current_user.id)
            db.session.add(chat)
            db.session.flush()

            owner_member = GroupChatMember(
                chat_id=chat.id, user_id=current_user.id, role="owner"
            )
            db.session.add(owner_member)

            db.session.commit()
            flash("Группа создана.", "success")
            return redirect(url_for("group_chat_detail", chat_id=chat.id))

        memberships = GroupChatMember.query.filter_by(user_id=current_user.id).all()
        chat_ids = [m.chat_id for m in memberships]
        chats = GroupChat.query.filter(GroupChat.id.in_(chat_ids)).order_by(
            GroupChat.created_at.desc()
        ).all() if chat_ids else []

        members_map: dict[int, str] = {}
        if chats:
            all_members = GroupChatMember.query.filter(
                GroupChatMember.chat_id.in_([c.id for c in chats])
            ).all()
            users = {u.id: u for u in User.query.filter(
                User.id.in_([m.user_id for m in all_members])
            ).all()}
            by_chat: dict[int, list[str]] = {}
            for m in all_members:
                user = users.get(m.user_id)
                if not user:
                    continue
                by_chat.setdefault(m.chat_id, []).append(user.username)
            for chat in chats:
                members_map[chat.id] = ", ".join(by_chat.get(chat.id, []))

        return render_template("group_chats.html", form=form, chats=chats, members_map=members_map)

    @app.route("/group_chats/<int:chat_id>", methods=["GET", "POST"])
    @login_required
    def group_chat_detail(chat_id: int):
        chat = GroupChat.query.get_or_404(chat_id)
        member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=current_user.id).first()
        if not member:
            abort(403)

        form = ChatMessageForm()
        if form.validate_on_submit():
            text_body = (form.body.data or "").strip()
            file = form.image.data
            sticker_id_val = form.sticker_id.data or request.form.get("sticker_id", type=int)

            image_filename = None
            if sticker_id_val:
                sticker = Sticker.query.get(sticker_id_val)
                if not sticker or sticker.pack.user_id != current_user.id:
                    flash("Стикер не найден или вам не принадлежит.", "danger")
                    return redirect(url_for("group_chat_detail", chat_id=chat.id))
                image_filename = sticker.image_filename
            elif file and file.filename:
                if not allowed_file(file.filename):
                    flash(
                        "Разрешены только изображения (png, jpg, jpeg, gif, webp).",
                        "danger",
                    )
                    return redirect(url_for("group_chat_detail", chat_id=chat.id))
                image_filename = save_image(file, app.config["UPLOAD_FOLDER"])

            if not text_body and not image_filename:
                flash("Введите текст, прикрепите файл или выберите стикер.", "warning")
                return redirect(url_for("group_chat_detail", chat_id=chat.id))

            msg = GroupMessage(
                chat_id=chat.id,
                sender_id=current_user.id,
                body=text_body or "",
                image_filename=image_filename,
            )
            db.session.add(msg)
            db.session.commit()
            return redirect(url_for("group_chat_detail", chat_id=chat.id))

        members = GroupChatMember.query.filter_by(chat_id=chat.id).all()
        messages = (
            GroupMessage.query.filter_by(chat_id=chat.id)
            .order_by(GroupMessage.created_at.asc())
            .all()
        )
        user_sticker_packs = (
            StickerPack.query.filter_by(user_id=current_user.id)
            .order_by(StickerPack.created_at.desc())
            .all()
        )
        is_owner = member.role == "owner"
        return render_template(
            "group_chat_detail.html",
            chat=chat,
            members=members,
            messages=messages,
            form=form,
            member=member,
            user_sticker_packs=user_sticker_packs,
            is_owner=is_owner,
        )

    @app.route("/group_chats/<int:chat_id>/settings", methods=["GET", "POST"])
    @login_required
    def group_chat_settings(chat_id: int):
        chat = GroupChat.query.get_or_404(chat_id)
        current_member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=current_user.id).first()
        is_owner = current_user.id == chat.owner_id
        if not current_member and not is_owner:
            abort(403)
        if current_member and current_member.role not in ("owner", "admin") and not is_owner:
            abort(403)
        if is_owner and not current_member:
            current_member = GroupChatMember(
                chat_id=chat.id, user_id=current_user.id, role="owner"
            )
            db.session.add(current_member)
            db.session.commit()
        elif is_owner and current_member and current_member.role != "owner":
            current_member.role = "owner"
            db.session.commit()

        members = GroupChatMember.query.filter_by(chat_id=chat.id).all()
        links = FriendLink.query.filter(
            or_(
                FriendLink.user1_id == current_user.id,
                FriendLink.user2_id == current_user.id,
            )
        ).filter(FriendLink.status == "accepted").all()
        friend_ids = {l.other_user_id(current_user.id) for l in links}
        member_ids = {m.user_id for m in members}
        candidate_ids = list(friend_ids - member_ids)
        friends_not_in_chat = []
        if candidate_ids:
            friends_not_in_chat = User.query.filter(User.id.in_(candidate_ids)).all()

        if request.method == "POST":
            if is_owner or (current_member and current_member.role == "owner"):
                new_name = (request.form.get("name") or "").strip()
                if new_name:
                    chat.name = new_name

                file = request.files.get("avatar")
                if file and file.filename:
                    if not allowed_file(file.filename):
                        flash(
                            "Разрешены только изображения (png, jpg, jpeg, gif, webp).",
                            "danger",
                        )
                    else:
                        filename = save_image(file, current_app.config["UPLOAD_FOLDER"])
                        chat.avatar_filename = filename

                db.session.commit()
                flash("Настройки группы обновлены.", "success")
            return redirect(url_for("group_chat_settings", chat_id=chat.id))

        return render_template(
            "group_chat_settings.html",
            chat=chat,
            members=members,
            current_member=current_member,
            is_owner=is_owner,
            friends_not_in_chat=friends_not_in_chat,
        )

    @app.route("/group_chats/<int:chat_id>/add_member/<int:user_id>", methods=["POST"])
    @login_required
    def group_chat_add_member(chat_id: int, user_id: int):
        chat = GroupChat.query.get_or_404(chat_id)
        current_member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=current_user.id).first()
        if not current_member or current_member.role not in ("owner", "admin"):
            abort(403)
        user = User.query.get_or_404(user_id)

        if not _are_friends(current_user.id, user.id):
            flash("Добавлять в группу можно только друзей.", "warning")
            return redirect(url_for("group_chat_detail", chat_id=chat.id))

        existing = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=user.id).first()
        if existing:
            flash("Этот пользователь уже в группе.", "info")
            return redirect(url_for("group_chat_detail", chat_id=chat.id))

        db.session.add(GroupChatMember(chat_id=chat.id, user_id=user.id))
        db.session.commit()
        flash(f"Пользователь {user.username} добавлен в группу.", "success")
        return redirect(url_for("group_chat_settings", chat_id=chat.id))

    @app.route("/group_chats/<int:chat_id>/remove_member/<int:user_id>", methods=["POST"])
    @login_required
    def group_chat_remove_member(chat_id: int, user_id: int):
        chat = GroupChat.query.get_or_404(chat_id)
        current_member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=current_user.id).first()
        if not current_member or current_member.role not in ("owner", "admin"):
            abort(403)

        member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=user_id).first_or_404()
        if member.role == "owner":
            flash("Нельзя удалить владельца группы.", "danger")
            return redirect(url_for("group_chat_settings", chat_id=chat.id))
        if current_member.role == "admin" and member.role != "member":
            flash("Админ может удалять только участников.", "danger")
            return redirect(url_for("group_chat_settings", chat_id=chat.id))

        db.session.delete(member)
        db.session.commit()
        flash("Участник удалён из группы.", "success")
        return redirect(url_for("group_chat_settings", chat_id=chat.id))

    @app.route("/group_chats/<int:chat_id>/members/<int:user_id>/role", methods=["POST"])
    @login_required
    def group_chat_change_role(chat_id: int, user_id: int):
        chat = GroupChat.query.get_or_404(chat_id)
        current_member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=current_user.id).first()
        if not current_member or current_member.role != "owner":
            abort(403)

        member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=user_id).first_or_404()
        if member.role == "owner":
            flash("Нельзя изменить роль владельца.", "danger")
            return redirect(url_for("group_chat_settings", chat_id=chat.id))

        new_role = (request.form.get("role") or "").strip()
        if new_role not in ("admin", "member"):
            flash("Некорректная роль.", "danger")
            return redirect(url_for("group_chat_settings", chat_id=chat.id))

        member.role = new_role
        db.session.commit()
        flash("Роль участника обновлена.", "success")
        return redirect(url_for("group_chat_settings", chat_id=chat.id))

    @app.route("/group_chats/<int:chat_id>/leave", methods=["POST"])
    @login_required
    def group_chat_leave(chat_id: int):
        chat = GroupChat.query.get_or_404(chat_id)
        member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=current_user.id).first()
        if not member:
            abort(403)
        if member.role == "owner":
            flash("Владелец не может покинуть группу.", "danger")
            return redirect(url_for("group_chat_settings", chat_id=chat.id))

        db.session.delete(member)
        db.session.commit()
        flash("Вы вышли из группы.", "success")
        return redirect(url_for("group_chats"))

    @app.route("/group_chats/<int:chat_id>/delete", methods=["POST"])
    @login_required
    def group_chat_delete(chat_id: int):
        chat = GroupChat.query.get_or_404(chat_id)
        member = GroupChatMember.query.filter_by(chat_id=chat.id, user_id=current_user.id).first()
        if not member or member.role != "owner":
            abort(403)
        db.session.delete(chat)
        db.session.commit()
        flash("Группа удалена.", "success")
        return redirect(url_for("group_chats"))

    @app.route("/api/group_chats/<int:chat_id>/messages")
    @login_required
    def group_chat_messages_api(chat_id: int):
        chat = GroupChat.query.get_or_404(chat_id)
        if not _ensure_group_member(chat, current_user):
            abort(403)

        after_id_raw = request.args.get("after_id", "").strip()
        try:
            after_id = int(after_id_raw) if after_id_raw else 0
        except ValueError:
            after_id = 0

        query = (
            GroupMessage.query.filter_by(chat_id=chat.id)
            .filter(GroupMessage.id > after_id)
            .order_by(GroupMessage.id.asc())
        )
        new_messages = query.all()

        def serialize(m: GroupMessage) -> dict:
            is_me = m.sender_id == current_user.id
            author_label = m.sender.username if m.sender else "Пользователь"
            image_url = (
                url_for("static", filename=os.path.join("uploads", m.image_filename))
                if m.image_filename
                else None
            )
            return {
                "id": m.id,
                "body": m.body or "",
                "created_at": m.created_at.strftime("%d.%m %H:%M"),
                "is_me": is_me,
                "author_label": author_label,
                "image_url": image_url,
            }

        return [serialize(m) for m in new_messages]

    @app.route("/chats/<int:conversation_id>", methods=["GET", "POST"])
    @login_required
    def chat_detail(conversation_id: int):
        conv = Conversation.query.get_or_404(conversation_id)
        if current_user.id not in (conv.user1_id, conv.user2_id):
            abort(403)

        other_user_id = conv.other_user_id(current_user.id)
        other = User.query.get_or_404(other_user_id)

        form = ChatMessageForm()
        if form.validate_on_submit():
            text_body = (form.body.data or "").strip()
            file = form.image.data
            sticker_id_val = form.sticker_id.data or request.form.get("sticker_id", type=int)

            image_filename = None
            if sticker_id_val:
                sticker = Sticker.query.get(sticker_id_val)
                if not sticker or sticker.pack.user_id != current_user.id:
                    flash("Стикер не найден или вам не принадлежит.", "danger")
                    return redirect(url_for("chat_detail", conversation_id=conv.id))
                image_filename = sticker.image_filename
            elif file and file.filename:
                if not allowed_file(file.filename):
                    flash("Разрешены только изображения (png, jpg, jpeg, gif, webp).", "danger")
                    return redirect(url_for("chat_detail", conversation_id=conv.id))
                image_filename = save_image(file, app.config["UPLOAD_FOLDER"])

            if not text_body and not image_filename:
                flash("Введите текст, прикрепите файл или выберите стикер.", "warning")
                return redirect(url_for("chat_detail", conversation_id=conv.id))

            reply_to_id = request.form.get("reply_to_id", type=int)
            if reply_to_id:
                reply_to_msg = Message.query.filter_by(id=reply_to_id, conversation_id=conv.id).first()
                if not reply_to_msg:
                    reply_to_id = None

            msg = Message(
                conversation_id=conv.id,
                sender_id=current_user.id,
                body=text_body or "",
                image_filename=image_filename,
                reply_to_id=reply_to_id,
            )
            conv.updated_at = datetime.utcnow()
            db.session.add(msg)

            bot = get_or_create_bot_user()
            if other.username == BOT_USERNAME:
                _handle_bot_sticker_commands(
                    current_user.id,
                    conv.id,
                    bot.id,
                    text_body or "",
                    image_filename,
                )

            db.session.commit()
            return redirect(url_for("chat_detail", conversation_id=conv.id))

        messages = (
            Message.query.filter_by(conversation_id=conv.id)
            .order_by(Message.created_at.asc())
            .all()
        )
        user_sticker_packs = (
            StickerPack.query.filter_by(user_id=current_user.id)
            .order_by(StickerPack.created_at.desc())
            .all()
        )
        today_date = datetime.utcnow().date()
        yesterday_date = today_date - timedelta(days=1)
        return render_template(
            "chat_detail.html",
            conversation=conv,
            other=other,
            messages=messages,
            form=form,
            is_bot_chat=(other.username == BOT_USERNAME),
            user_sticker_packs=user_sticker_packs,
            today_date=today_date,
            yesterday_date=yesterday_date,
        )

    @app.route("/chats/<int:conversation_id>/delete", methods=["POST"])
    @login_required
    def chat_delete(conversation_id: int):
        conv = Conversation.query.get_or_404(conversation_id)
        if current_user.id not in (conv.user1_id, conv.user2_id):
            abort(403)
        db.session.delete(conv)
        db.session.commit()
        flash("Чат удалён.", "success")
        return redirect(url_for("chats"))

    @app.route("/api/chats/<int:conversation_id>/messages")
    @login_required
    def chat_messages_api(conversation_id: int):
        conv = Conversation.query.get_or_404(conversation_id)
        if current_user.id not in (conv.user1_id, conv.user2_id):
            abort(403)

        after_id_raw = request.args.get("after_id", "").strip()
        try:
            after_id = int(after_id_raw) if after_id_raw else 0
        except ValueError:
            after_id = 0

        query = (
            Message.query.filter_by(conversation_id=conv.id)
            .filter(Message.id > after_id)
            .order_by(Message.id.asc())
        )
        new_messages = query.all()

        def serialize(m: Message) -> dict:
            is_me = m.sender_id == current_user.id
            author_label = "Вы" if is_me else (m.sender.username if m.sender else "Пользователь")
            image_url = (
                url_for("static", filename=os.path.join("uploads", m.image_filename))
                if m.image_filename
                else None
            )
            sticker_pack = None
            if m.sticker_pack:
                sticker_pack = {
                    "name": m.sticker_pack.name,
                    "sticker_urls": [
                        url_for("static", filename=os.path.join("uploads", s.image_filename))
                        for s in m.sticker_pack.stickers
                    ],
                }
            reply_to = None
            if m.reply_to:
                rt = m.reply_to
                rt_author = "Вы" if rt.sender_id == current_user.id else (rt.sender.username if rt.sender else "")
                reply_to = {
                    "id": rt.id,
                    "body": (rt.body or "")[:80] + ("…" if (rt.body or "").__len__() > 80 else ""),
                    "author_label": rt_author,
                }
            return {
                "id": m.id,
                "body": m.body or "",
                "created_at": m.created_at.strftime("%d.%m %H:%M"),
                "date_key": m.created_at.strftime("%Y-%m-%d"),
                "is_me": is_me,
                "author_label": author_label,
                "image_url": image_url,
                "sticker_pack": sticker_pack,
                "reply_to": reply_to,
            }

        return [serialize(m) for m in new_messages]

    @app.route("/api/chats/<int:conversation_id>/messages", methods=["POST"])
    @login_required
    def chat_send_message_api(conversation_id: int):
        conv = Conversation.query.get_or_404(conversation_id)
        if current_user.id not in (conv.user1_id, conv.user2_id):
            abort(403)
        text_body = (request.form.get("body") or "").strip()
        file = request.files.get("image")
        sticker_id_val = request.form.get("sticker_id", type=int)
        reply_to_id = request.form.get("reply_to_id", type=int)

        image_filename = None
        if sticker_id_val:
            sticker = Sticker.query.get(sticker_id_val)
            if not sticker or sticker.pack.user_id != current_user.id:
                return {"ok": False, "error": "Стикер не найден."}, 400
            image_filename = sticker.image_filename
        elif file and file.filename:
            if not allowed_file(file.filename):
                return {"ok": False, "error": "Только изображения."}, 400
            image_filename = save_image(file, app.config["UPLOAD_FOLDER"])

        if not text_body and not image_filename:
            return {"ok": False, "error": "Введите текст или прикрепите файл/стикер."}, 400

        reply_to_msg = None
        if reply_to_id:
            reply_to_msg = Message.query.filter_by(id=reply_to_id, conversation_id=conv.id).first()
            if not reply_to_msg:
                reply_to_id = None

        msg = Message(
            conversation_id=conv.id,
            sender_id=current_user.id,
            body=text_body or "",
            image_filename=image_filename,
            reply_to_id=reply_to_id,
        )
        conv.updated_at = datetime.utcnow()
        db.session.add(msg)

        other_user_id = conv.other_user_id(current_user.id)
        other = User.query.get_or_404(other_user_id)
        bot = get_or_create_bot_user()
        if other.username == BOT_USERNAME:
            _handle_bot_sticker_commands(
                current_user.id, conv.id, bot.id, text_body or "", image_filename
            )

        db.session.commit()

        is_me = True
        author_label = "Вы"
        image_url = url_for("static", filename=os.path.join("uploads", msg.image_filename)) if msg.image_filename else None
        sticker_pack = None
        if msg.sticker_pack:
            sticker_pack = {
                "name": msg.sticker_pack.name,
                "sticker_urls": [
                    url_for("static", filename=os.path.join("uploads", s.image_filename))
                    for s in msg.sticker_pack.stickers
                ],
            }
        reply_to = None
        if msg.reply_to:
            rt = msg.reply_to
            reply_to = {"id": rt.id, "body": (rt.body or "")[:80] + ("…" if len(rt.body or "") > 80 else ""), "author_label": "Вы" if rt.sender_id == current_user.id else (rt.sender.username if rt.sender else "")}
        return {
            "ok": True,
            "message": {
                "id": msg.id,
                "body": msg.body or "",
                "created_at": msg.created_at.strftime("%d.%m %H:%M"),
                "date_key": msg.created_at.strftime("%Y-%m-%d"),
                "is_me": is_me,
                "author_label": author_label,
                "image_url": image_url,
                "sticker_pack": sticker_pack,
                "reply_to": reply_to,
            },
        }

    @app.route("/api/chats/<int:conversation_id>/messages/<int:message_id>", methods=["DELETE"])
    @login_required
    def chat_delete_message_api(conversation_id: int, message_id: int):
        conv = Conversation.query.get_or_404(conversation_id)
        if current_user.id not in (conv.user1_id, conv.user2_id):
            abort(403)
        msg = Message.query.filter_by(id=message_id, conversation_id=conv.id).first_or_404()
        if msg.sender_id != current_user.id and not current_user.is_admin:
            abort(403)
        db.session.delete(msg)
        db.session.commit()
        return {"ok": True}


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def not_found(error):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("500.html"), 500


if __name__ == "__main__":
    application = create_app()
    application.run(debug=True)
