from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Admin(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # Optional email for email-based login
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Admin {self.username}>'

class Customer(db.Model):
    __bind_key__ = 'customer'
    __tablename__ = 'customers'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    addresses = db.relationship('Address', backref='customer', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Customer {self.username}>'

class Address(db.Model):
    __bind_key__ = 'customer'
    __tablename__ = 'addresses'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    address_type = db.Column(db.String(20), nullable=False)  # 'home', 'work', 'other'
    address_line1 = db.Column(db.String(255), nullable=False)
    address_line2 = db.Column(db.String(255))
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    landmark = db.Column(db.String(255))
    country = db.Column(db.String(100))
    alternative_phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Address {self.address_type} - {self.customer_id}>'


class Category(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    threads = db.relationship('Thread', backref='category', lazy=True, cascade='all, delete')

    def __repr__(self):
        return f'<Category {self.name}>'


class Vendor(db.Model):
    __bind_key__ = 'vendor'
    __tablename__ = 'vendors'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    business_name = db.Column(db.String(100))
    business_type = db.Column(db.String(100))
    address = db.Column(db.Text)
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))
    
    # Verification
    verification_status = db.Column(db.String(50), default='not-submitted')
    admin_remarks = db.Column(db.Text)
    
    # Configuration
    commission_rate = db.Column(db.Float, default=15.0)
    payment_cycle = db.Column(db.String(50), default= 'monthly')
    service_zone = db.Column(db.String(50), default='all')
    
    # Location
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    current_address = db.Column(db.String(255))
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    pincode = db.Column(db.String(20))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Vendor {self.username}>'

class VendorDocument(db.Model):
    __bind_key__ = 'vendor'
    __tablename__ = 'vendor_documents'
    
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=False, unique=True)
    
    # Documents (Binary Data) and Metadata (JSON: filename, mimetype, size, status, remarks)
    pan = db.Column(db.LargeBinary)
    pan_meta = db.Column(db.JSON)
    pan_number = db.Column(db.String(20))
    
    aadhar = db.Column(db.LargeBinary)
    aadhar_meta = db.Column(db.JSON)
    aadhar_number = db.Column(db.String(20))
    
    gst = db.Column(db.LargeBinary)
    gst_meta = db.Column(db.JSON)
    gst_number = db.Column(db.String(20))
    
    business = db.Column(db.LargeBinary)
    business_meta = db.Column(db.JSON)
    
    bank = db.Column(db.LargeBinary)
    bank_meta = db.Column(db.JSON)
    bank_account_number = db.Column(db.String(50))
    bank_holder_name = db.Column(db.String(100))
    bank_branch = db.Column(db.String(100))
    ifsc_code = db.Column(db.String(20))
    
    workshop = db.Column(db.LargeBinary)
    workshop_meta = db.Column(db.JSON)
    
    signature = db.Column(db.LargeBinary)
    signature_meta = db.Column(db.JSON)
    
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    vendor = db.relationship('Vendor', backref=db.backref('document_row', uselist=False, lazy=True))

    def __repr__(self):
        return f'<VendorDocument Row for Vendor {self.vendor_id}>'

class VendorQuotationSubmission(db.Model):
    __bind_key__ = 'vendor'
    """Post-approval quotation and commission rate submission"""
    __tablename__ = 'vendor_quotation_submissions'
    
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=False, unique=True)
    
    # Quotation file
    quotation_file = db.Column(db.LargeBinary)
    quotation_filename = db.Column(db.String(255))
    quotation_mimetype = db.Column(db.String(100))
    
    # Commission rate proposed by vendor
    proposed_commission_rate = db.Column(db.Float)
    
    # Status: 'pending', 'approved', 'rejected'
    status = db.Column(db.String(50), default='pending')
    admin_remarks = db.Column(db.Text)
    
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    
    # Relationship
    vendor = db.relationship('Vendor', backref=db.backref('quotation_submission', uselist=False, lazy=True))
    
    def __repr__(self):
        return f'<VendorQuotationSubmission for Vendor {self.vendor_id}>'

class RiderDocument(db.Model):
    __bind_key__ = 'rider'
    """Rider verification documents"""
    __tablename__ = 'rider_documents'
    
    id = db.Column(db.Integer, primary_key=True)
    rider_id = db.Column(db.Integer, db.ForeignKey('riders.id'), nullable=False, unique=True)
    
    # Documents (Binary Data) and Metadata (JSON: filename, mimetype, size, status, remarks)
    aadhar = db.Column(db.LargeBinary)
    aadhar_meta = db.Column(db.JSON)
    aadhar_number = db.Column(db.String(20))
    
    dl = db.Column(db.LargeBinary)  # Driving License
    dl_meta = db.Column(db.JSON)
    dl_number = db.Column(db.String(50))
    dl_name = db.Column(db.String(100))
    dl_validity = db.Column(db.String(50))
    
    pan = db.Column(db.LargeBinary)
    pan_meta = db.Column(db.JSON)
    pan_number = db.Column(db.String(20))
    
    photo = db.Column(db.LargeBinary)  # Profile Photo
    photo_meta = db.Column(db.JSON)
    
    vehicle_rc = db.Column(db.LargeBinary)  # Vehicle Registration Certificate
    vehicle_rc_meta = db.Column(db.JSON)
    vehicle_rc_number = db.Column(db.String(50))
    
    insurance = db.Column(db.LargeBinary)  # Vehicle Insurance
    insurance_meta = db.Column(db.JSON)
    insurance_policy_number = db.Column(db.String(50))

    bank = db.Column(db.LargeBinary)
    bank_meta = db.Column(db.JSON)
    bank_account_number = db.Column(db.String(50))
    bank_holder_name = db.Column(db.String(100))
    bank_branch = db.Column(db.String(100))
    ifsc_code = db.Column(db.String(20))
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    rider = db.relationship('Rider', backref=db.backref('document_row', uselist=False, lazy=True))
    
    def __repr__(self):
        return f'<RiderDocument Row for Rider {self.rider_id}>'

class Order(db.Model):
    __bind_key__ = 'customer'
    __tablename__ = 'orders'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    selected_vendor_id = db.Column(db.Integer, nullable=True)  # Cross-schema: references vendor schema
    
    # Product Details
    product_type = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    neck_type = db.Column(db.String(50))
    color = db.Column(db.String(30))
    fabric = db.Column(db.String(50))
    print_type = db.Column(db.String(50))
    
    # Quantity & Price
    quantity = db.Column(db.Integer, nullable=False)
    price_per_piece_offered = db.Column(db.Float)  # Customer's offer
    quotation_price_per_piece = db.Column(db.Float)  # Final agreed price
    quotation_total_price = db.Column(db.Float)
    sample_cost = db.Column(db.Float, default=0.0)
    sample_size = db.Column(db.String(10))
    
    # Delivery
    delivery_date = db.Column(db.String(20))
    address_line1 = db.Column(db.String(255), nullable=False)
    address_line2 = db.Column(db.String(255))
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    country = db.Column(db.String(100))
    
    # Status & Feedback
    status = db.Column(db.String(50), default='pending_admin_review')
    rating = db.Column(db.Integer)
    delivery_on_time = db.Column(db.Boolean)
    delivery_delay_days = db.Column(db.Integer, default=0)
    defect_reported = db.Column(db.Boolean, default=False)
    feedback_comment = db.Column(db.Text)
    
    # Financials
    vendor_initial_payout = db.Column(db.Float, default=0.0)
    vendor_final_payout = db.Column(db.Float, default=0.0)
    penalty_amount_total = db.Column(db.Float, default=0.0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    customer = db.relationship('Customer', backref='orders')
    # vendor relationship removed - cross-schema reference

    def __repr__(self):
        return f'<Order {self.id} - {self.status}>'


class OrderStatusHistory(db.Model):
    """Tracks all status changes for orders - enables real-time tracking"""
    __bind_key__ = 'customer'
    __tablename__ = 'order_status_history'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    
    # Status Information
    status = db.Column(db.String(50), nullable=False)
    status_label = db.Column(db.String(100))  # Human-readable label
    
    # Who made the change
    changed_by_type = db.Column(db.String(20), nullable=False)  # 'admin', 'vendor', 'system', 'customer'
    changed_by_id = db.Column(db.Integer)  # ID of the user who made the change
    
    # Additional info
    notes = db.Column(db.Text)  # Optional notes about the status change
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    order = db.relationship('Order', backref=db.backref('status_history', lazy='dynamic', order_by='OrderStatusHistory.created_at'))
    
    def __repr__(self):
        return f'<OrderStatusHistory {self.order_id} -> {self.status}>'

class CustomerPayment(db.Model):
    """Payment model for customer database - internal payment tracking"""
    __bind_key__ = 'customer'
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    payer_type = db.Column(db.String(20), nullable=False) # 'customer', 'admin'
    payer_id = db.Column(db.Integer, nullable=False)
    receiver_type = db.Column(db.String(20), nullable=False) # 'admin', 'vendor'
    receiver_id = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_type = db.Column(db.String(50), nullable=False) # 'sample_payment', 'advance_50', etc.
    status = db.Column(db.String(20), default='completed')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    order = db.relationship('Order', backref='customer_payments')

class Notification(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False) # Vendor ID or Customer ID
    user_type = db.Column(db.String(20), default='vendor') # 'vendor', 'customer', 'admin'
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50)) # 'order', 'payment', 'verification', 'system'
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Notification {self.id} - {self.title}>'


class Thread(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'threads'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)  # Cross-schema: references customer schema
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    comments = db.relationship('Comment', backref='thread', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Thread {self.id} - {self.title}>'


class Comment(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)  # Cross-schema: references customer schema
    thread_id = db.Column(db.Integer, db.ForeignKey('threads.id'), nullable=False)
    parent_comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    replies = db.relationship(
        'Comment',
        backref=db.backref('parent', remote_side=[id]),
        lazy=True,
        cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f'<Comment {self.id} on Thread {self.thread_id}>'

class Rider(db.Model):
    __bind_key__ = 'rider'
    """Rider - Self-registration model for delivery partners"""
    __tablename__ = 'riders'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Vehicle Information
    vehicle_type = db.Column(db.String(50))  # 'bike', 'scooter', 'bicycle', 'car'
    vehicle_number = db.Column(db.String(50))
    
    # Service Zone
    service_zone = db.Column(db.String(100))  # City/Area
    
    # Profile
    profile_picture_url = db.Column(db.String(255))
    bio = db.Column(db.Text)
    
    # ID Proof Documents (stored as binary)
    dl_document = db.Column(db.LargeBinary)
    dl_filename = db.Column(db.String(255))
    dl_mimetype = db.Column(db.String(100))
    
    aadhar_document = db.Column(db.LargeBinary)
    aadhar_filename = db.Column(db.String(255))
    aadhar_mimetype = db.Column(db.String(100))
    
    # Verification Status
    verification_status = db.Column(db.String(50), default='not-submitted')
    # 'not-submitted', 'pending', 'under-review', 'approved', 'rejected'
    admin_remarks = db.Column(db.Text)
    
    # Availability
    is_online = db.Column(db.Boolean, default=False)
    last_online_at = db.Column(db.DateTime)
    
    # Live Location
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    current_address = db.Column(db.String(255))
    
    # Earnings
    total_earnings = db.Column(db.Float, default=0.0)
    pending_payout = db.Column(db.Float, default=0.0)
    
    # Performance Metrics
    total_deliveries = db.Column(db.Integer, default=0)
    successful_deliveries = db.Column(db.Integer, default=0)
    failed_deliveries = db.Column(db.Integer, default=0)
    average_rating = db.Column(db.Float, default=0.0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    deliveries = db.relationship('DeliveryLog', backref='assigned_rider', lazy=True, foreign_keys='DeliveryLog.assigned_rider_id')
    
    def __repr__(self):
        return f'<Rider {self.name} - {self.email}>'

class DeliveryPartner(db.Model):
    __bind_key__ = 'rider'
    """Delivery Partner (Rider) - Admin-added only, no self-registration"""
    __tablename__ = 'delivery_partners'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Vehicle Information
    vehicle_type = db.Column(db.String(50))  # 'Bike', 'Scooty', etc.
    vehicle_number = db.Column(db.String(50))
    
    # Service Zone
    service_zone = db.Column(db.String(100))  # City/Area assigned
    
    # Availability
    is_online = db.Column(db.Boolean, default=False)
    last_online_at = db.Column(db.DateTime)
    
    # Live Location
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    current_address = db.Column(db.String(255))
    
    # Profile
    profile_picture_url = db.Column(db.String(255))
    
    # ID Proof Documents (stored as binary)
    dl_document = db.Column(db.LargeBinary)
    dl_filename = db.Column(db.String(255))
    aadhar_document = db.Column(db.LargeBinary)
    aadhar_filename = db.Column(db.String(255))
    
    # Status
    status = db.Column(db.String(50), default='pending_verification')  # 'active', 'suspended', 'inactive', 'pending_verification'
    
    # Earnings
    total_earnings = db.Column(db.Float, default=0.0)
    pending_payout = db.Column(db.Float, default=0.0)
    
    # Performance Metrics
    total_deliveries = db.Column(db.Integer, default=0)
    successful_deliveries = db.Column(db.Integer, default=0)
    failed_deliveries = db.Column(db.Integer, default=0)
    average_rating = db.Column(db.Float, default=0.0)
    
    # Admin Contact
    admin_contact = db.Column(db.String(20))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    deliveries = db.relationship('DeliveryLog', backref='rider', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<DeliveryPartner {self.name} - {self.phone}>'

class DeliveryLog(db.Model):
    __bind_key__ = 'rider'
    """Delivery tracking and proof logs"""
    __tablename__ = 'delivery_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, nullable=False)  # Cross-schema: references customer.orders
    rider_id = db.Column(db.Integer, db.ForeignKey('delivery_partners.id'), nullable=True)  # For admin-added riders
    assigned_rider_id = db.Column(db.Integer, db.ForeignKey('riders.id'), nullable=True)  # For self-registered riders
    
    # Pickup Details
    vendor_address = db.Column(db.Text)
    vendor_contact = db.Column(db.String(20))
    
    # Delivery Details
    customer_address = db.Column(db.Text)
    customer_contact = db.Column(db.String(20))
    
    # Status Tracking
    status = db.Column(db.String(50), default='assigned')  
    # 'assigned', 'reached_vendor', 'picked_up', 'out_for_delivery', 'delivered', 'failed', 'returned'
    
    # Timestamps
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    reached_vendor_at = db.Column(db.DateTime)
    picked_up_at = db.Column(db.DateTime)
    out_for_delivery_at = db.Column(db.DateTime)
    delivered_at = db.Column(db.DateTime)
    
    # Delivery Deadline
    delivery_deadline = db.Column(db.DateTime)
    
    # Priority
    is_urgent = db.Column(db.Boolean, default=False)
    
    # Proof Images (stored as binary)
    pickup_proof_image = db.Column(db.LargeBinary)
    pickup_proof_filename = db.Column(db.String(255))
    delivery_proof_image = db.Column(db.LargeBinary)
    delivery_proof_filename = db.Column(db.String(255))
    
    # Notes
    pickup_notes = db.Column(db.Text)
    delivery_notes = db.Column(db.Text)
    
    # OTP Verification (optional)
    delivery_otp = db.Column(db.String(6))
    otp_verified = db.Column(db.Boolean, default=False)
    
    # Live Location Tracking
    current_latitude = db.Column(db.Float)
    current_longitude = db.Column(db.Float)
    last_location_update = db.Column(db.DateTime)
    
    # Earnings for this delivery
    base_payout = db.Column(db.Float, default=0.0)
    distance_bonus = db.Column(db.Float, default=0.0)
    incentive = db.Column(db.Float, default=0.0)
    total_earning = db.Column(db.Float, default=0.0)
    payout_status = db.Column(db.String(50), default='pending')  # 'pending', 'released', 'on_hold'
    
    # Proofs
    pickup_proof = db.Column(db.LargeBinary)
    pickup_proof_filename = db.Column(db.String(255))
    delivery_proof = db.Column(db.LargeBinary)
    delivery_proof_filename = db.Column(db.String(255))
    notes = db.Column(db.Text)
    
    # Customer Rating
    customer_rating = db.Column(db.Integer)  # 1-5 stars
    
    # Relationships
    # order relationship removed - cross-schema reference
    
    def __repr__(self):
        return f'<DeliveryLog Order#{self.order_id} - Rider#{self.rider_id} - {self.status}>'

class Support(db.Model):
    __bind_key__ = 'support'
    """Support staff model for support database"""
    __tablename__ = 'support_staff'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Support {self.username} - {self.email}>'

class SupportTicket(db.Model):
    __bind_key__ = 'admin'
    """Support tickets for all user types"""
    __tablename__ = 'support_tickets'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'customer', 'vendor', 'rider'
    
    category = db.Column(db.String(50), nullable=False)  # 'delivery_issue', 'payment_issue', 'technical_issue', 'other'
    subject = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    # Attachments
    attachment_image = db.Column(db.LargeBinary)
    attachment_filename = db.Column(db.String(255))
    
    # Status
    status = db.Column(db.String(50), default='open')  # 'open', 'in_progress', 'resolved', 'closed'
    priority = db.Column(db.String(20), default='normal')  # 'low', 'normal', 'high', 'urgent'
    
    # Admin Response
    admin_response = db.Column(db.Text)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<SupportTicket #{self.id} - {self.user_type} - {self.status}>'

class ProductCatalog(db.Model):
    __bind_key__ = 'admin'
    """
    Master product catalog containing all product variants with average pricing
    """
    __tablename__ = 'product_catalog'
    
    id = db.Column(db.Integer, primary_key=True)
    product_type = db.Column(db.String(100), nullable=False)  # T-Shirt, Polo T-Shirt, Hoodie, etc.
    category = db.Column(db.String(50), nullable=False)  # Men, Unisex
    neck_type = db.Column(db.String(50), nullable=False)  # Crew Neck, V-Neck, Polo Collar, etc.
    fabric = db.Column(db.String(50), nullable=False)  # Cotton, Fleece, Pique Cot
    size = db.Column(db.String(10), nullable=False)  # S, M, L, XL, XXL
    notes = db.Column(db.String(255))  # Standard Crew Neck Tee, V-Neck Tee, etc.
    
    # Pricing
    average_price = db.Column(db.Float, default=0.0)  # Average price across all vendors
    final_price = db.Column(db.Float, default=0.0)  # Average price + 40% margin
    vendor_count = db.Column(db.Integer, default=0)  # Number of vendors offering this product
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    # vendor_quotations relationship removed - cross-schema reference
    
    # Unique constraint to prevent duplicate products
    __table_args__ = (
        db.UniqueConstraint('product_type', 'category', 'neck_type', 'fabric', 'size', name='unique_product_variant'),
        {'extend_existing': True}
    )
    
    def __repr__(self):
        return f'<ProductCatalog {self.product_type} - {self.category} - {self.size}>'

class VendorQuotation(db.Model):
    __bind_key__ = 'vendor'
    """
    Individual vendor pricing for each product
    """
    __tablename__ = 'vendor_quotations'
    
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=False)
    product_id = db.Column(db.Integer, nullable=False)  # Cross-schema: references admin.product_catalog
    
    # Pricing
    base_cost = db.Column(db.Float, nullable=False)  # Vendor's quoted price
    
    # Status
    status = db.Column(db.String(50), default='pending')  # pending, approved, rejected
    admin_remarks = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    vendor = db.relationship('Vendor', backref='quotations', lazy=True)
    # product relationship removed - cross-schema reference
    
    # Unique constraint: one price per vendor per product
    __table_args__ = (
        db.UniqueConstraint('vendor_id', 'product_id', name='unique_vendor_product'),
        {'extend_existing': True}
    )
    
    def __repr__(self):
        return f'<VendorQuotation Vendor#{self.vendor_id} Product#{self.product_id} - ₹{self.base_cost}>'

class VendorOrderAssignment(db.Model):
    __bind_key__ = 'vendor'
    __tablename__ = 'vendor_order_assignments'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, nullable=False) # Refers to customer.Order
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=False)
    
    # Status: 'pending', 'accepted', 'rejected'
    status = db.Column(db.String(50), default='pending')
    rejection_reason = db.Column(db.Text)
    
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime)
    
    vendor = db.relationship('Vendor', backref='order_assignments', lazy=True)
    
    def __repr__(self):
        return f'<VendorOrderAssignment Order#{self.order_id} to Vendor#{self.vendor_id}>'

class OTPLog(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'otp_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    recipient = db.Column(db.String(255), nullable=False)
    otp_code = db.Column(db.String(10), nullable=False)
    type = db.Column(db.String(50)) # 'email', 'phone'
    status = db.Column(db.String(50), default='sent')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<OTPLog {self.recipient} - {self.otp_code}>'

class Payment(db.Model):
    """Payment transactions history for all payment types - Admin database"""
    __bind_key__ = 'admin'
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Transaction Details
    transaction_id = db.Column(db.String(100), unique=True, nullable=False)
    order_id = db.Column(db.Integer, nullable=False)  # References order across schemas
    customer_id = db.Column(db.Integer, nullable=False)  # References customer across schemas
    
    # Payment Type
    payment_type = db.Column(db.String(50), nullable=False)  # 'sample', 'bulk_order', 'advance', 'balance'
    payment_method = db.Column(db.String(50), nullable=False)  # 'card', 'upi', 'netbanking', 'cod'
    
    # Amount Details
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), default='INR')
    
    # Payment Status
    status = db.Column(db.String(50), default='pending')  # 'pending', 'success', 'failed', 'refunded'
    
    # Payment Method Specific Data (stored as JSON-like text)
    payment_details = db.Column(db.Text)  # e.g., card last 4 digits, UPI ID, bank name
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    
    # Vendor payout tracking (for admin)
    vendor_id = db.Column(db.Integer)  # Which vendor this payment relates to
    commission_amount = db.Column(db.Float)  # Admin commission
    vendor_payout_amount = db.Column(db.Float)  # Amount to be paid to vendor
    payout_status = db.Column(db.String(50), default='pending')  # 'pending', 'on_hold', 'approved', 'paid'
    payout_date = db.Column(db.DateTime)
    
    # Notes
    notes = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Payment {self.transaction_id} - ₹{self.amount}>'

