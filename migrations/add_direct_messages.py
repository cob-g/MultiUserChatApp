from app import db

def upgrade():
    # Create DirectMessage table
    db.create_table('direct_message', [
        db.Column('id', db.Integer, primary_key=True),
        db.Column('sender_username', db.String(80), nullable=False),
        db.Column('receiver_username', db.String(80), nullable=False),
        db.Column('content', db.Text, nullable=False),
        db.Column('timestamp', db.DateTime, server_default=db.func.now()),
        db.Column('is_read', db.Boolean, default=False)
    ])

def downgrade():
    # Drop DirectMessage table
    db.drop_table('direct_message') 