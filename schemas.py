from flask_marshmallow import Marshmallow
from marshmallow import fields
from models import (
    Admin,
    Customer,
    Vendor,
    Address,
    Order,
    VendorQuotation,
    ProductCatalog,
    Payment,
    Category,
    Thread,
    Comment,
    Rider,
    DeliveryPartner,
    DeliveryLog,
    DeliveryLog,
    SupportTicket,
    OTPLog,
)


ma = Marshmallow()

class AdminSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Admin
        load_instance = True
        fields = ('id', 'username', 'created_at')

class CustomerSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Customer
        load_instance = True
        fields = ('id', 'username', 'email', 'phone', 'bio', 'avatar_url', 'created_at')

class VendorSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Vendor
        load_instance = True
        fields = ('id', 'username', 'email', 'phone', 'business_name', 'business_type', 'address', 
                  'bio', 'avatar_url', 'verification_status', 'admin_remarks', 'commission_rate', 
                  'payment_cycle', 'service_zone', 'latitude', 'longitude', 'current_address', 
                  'city', 'state', 'pincode', 'created_at')

class AddressSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Address
        load_instance = True
        include_fk = True

class VendorQuotationSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = VendorQuotation
        load_instance = True
        include_fk = True
        fields = ('id', 'vendor_id', 'product_id', 'base_cost', 'status', 'admin_remarks', 'created_at', 'updated_at')
    vendor = ma.Nested(VendorSchema, only=('id', 'business_name', 'username'))

class ProductCatalogSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ProductCatalog
        load_instance = True
        fields = ('id', 'product_type', 'category', 'neck_type', 'fabric', 'size', 'notes', 
                  'average_price', 'final_price', 'vendor_count', 'created_at', 'updated_at')

class PaymentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Payment
        load_instance = True
        include_fk = True

class OrderSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Order
        load_instance = True
        include_fk = True
    customer = ma.Nested(CustomerSchema, only=('id', 'username', 'email', 'phone'))
    # Cross-schema fetch for vendor
    vendor = fields.Method("get_vendor")
    payments = fields.Method("get_payments")

    def get_vendor(self, obj):
        if obj.selected_vendor_id:
            vendor = Vendor.query.get(obj.selected_vendor_id)
            if vendor:
                return VendorSchema(only=('id', 'business_name', 'username', 'phone')).dump(vendor)
        return None

    def get_payments(self, obj):
        """Manually fetch payments from both admin and customer Payment models (cross-schema)"""
        from models import Payment, CustomerPayment
        admin_payments = Payment.query.filter_by(order_id=obj.id).all()
        customer_payments = CustomerPayment.query.filter_by(order_id=obj.id).all()
        
        result = []
        if admin_payments:
            result.extend(PaymentSchema(many=True).dump(admin_payments))
        if customer_payments:
            # Convert customer payments to dict format
            for p in customer_payments:
                result.append({
                    'id': p.id,
                    'type': 'internal',
                    'payer_type': p.payer_type,
                    'payer_id': p.payer_id,
                    'receiver_type': p.receiver_type,
                    'receiver_id': p.receiver_id,
                    'payment_type': p.payment_type,
                    'amount': p.amount,
                    'status': p.status,
                    'timestamp': p.timestamp.isoformat() if p.timestamp else None
                })
        return result


class CategorySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Category
        load_instance = True


class ThreadSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Thread
        load_instance = True
        include_fk = True
    category = ma.Nested(CategorySchema, only=('id', 'name'))
    user = fields.Method("get_user")

    def get_user(self, obj):
        if obj.user_id:
            # Assuming user_id refers to Customer (from original models)
            user = Customer.query.get(obj.user_id)
            if user:
                return CustomerSchema(only=('id', 'username')).dump(user)
        return None


class CommentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Comment
        load_instance = True
        include_fk = True
    user = fields.Method("get_user")

    def get_user(self, obj):
        if obj.user_id:
            user = Customer.query.get(obj.user_id)
            if user:
                return CustomerSchema(only=('id', 'username')).dump(user)
        return None

# Initialize Schemas
admin_schema = AdminSchema()
admins_schema = AdminSchema(many=True)

customer_schema = CustomerSchema()
customers_schema = CustomerSchema(many=True)

vendor_schema = VendorSchema()
vendors_schema = VendorSchema(many=True)

address_schema = AddressSchema()
addresses_schema = AddressSchema(many=True)

vendor_quotation_schema = VendorQuotationSchema()
vendor_quotations_schema = VendorQuotationSchema(many=True)

product_catalog_schema = ProductCatalogSchema()
product_catalogs_schema = ProductCatalogSchema(many=True)

payment_schema = PaymentSchema()
payments_schema = PaymentSchema(many=True)

order_schema = OrderSchema()
orders_schema = OrderSchema(many=True)

category_schema = CategorySchema()
categories_schema = CategorySchema(many=True)

thread_schema = ThreadSchema()
threads_schema = ThreadSchema(many=True)

comment_schema = CommentSchema()
comments_schema = CommentSchema(many=True)

# Rider Schemas
class RiderSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Rider
        load_instance = True
        fields = ('id', 'name', 'email', 'phone', 'vehicle_type', 'vehicle_number',
                  'service_zone', 'profile_picture_url', 'bio', 'verification_status', 'admin_remarks',
                  'is_online', 'last_online_at', 'latitude', 'longitude', 'current_address',
                  'total_earnings', 'pending_payout', 'total_deliveries', 'successful_deliveries', 
                  'failed_deliveries', 'average_rating', 'created_at', 'updated_at')

rider_schema = RiderSchema()
riders_schema = RiderSchema(many=True)

# Delivery Partner Schemas
class DeliveryPartnerSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = DeliveryPartner
        load_instance = True
        fields = ('id', 'name', 'phone', 'email', 'vehicle_type', 'vehicle_number', 
                  'service_zone', 'is_online', 'last_online_at', 'profile_picture_url',
                  'status', 'total_earnings', 'pending_payout', 'total_deliveries',
                  'successful_deliveries', 'failed_deliveries', 'average_rating',
                  'admin_contact', 'created_at', 'updated_at')

class DeliveryLogSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = DeliveryLog
        load_instance = True
        include_fk = True
    rider = fields.Method("get_rider")
    assigned_rider = fields.Method("get_assigned_rider")
    order = fields.Method("get_order")

    def get_rider(self, obj):
        """Get DeliveryPartner if rider_id is set"""
        if obj.rider_id:
            rider = DeliveryPartner.query.get(obj.rider_id)
            if rider:
                return DeliveryPartnerSchema(only=('id', 'name', 'phone', 'vehicle_type')).dump(rider)
        return None

    def get_assigned_rider(self, obj):
        """Get Rider if assigned_rider_id is set"""
        if obj.assigned_rider_id:
            rider = Rider.query.get(obj.assigned_rider_id)
            if rider:
                return RiderSchema(only=('id', 'name', 'email', 'phone', 'vehicle_type')).dump(rider)
        return None

    def get_order(self, obj):
        if obj.order_id:
            order = Order.query.get(obj.order_id)
            if order:
                return OrderSchema(only=('id', 'product_type', 'quantity', 'delivery_date')).dump(order)
        return None

class SupportTicketSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = SupportTicket
        load_instance = True
        include_fk = True

delivery_partner_schema = DeliveryPartnerSchema()
delivery_partners_schema = DeliveryPartnerSchema(many=True)

delivery_log_schema = DeliveryLogSchema()
delivery_logs_schema = DeliveryLogSchema(many=True)

support_ticket_schema = SupportTicketSchema()
support_tickets_schema = SupportTicketSchema(many=True)

class OTPLogSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = OTPLog
        load_instance = True

otp_log_schema = OTPLogSchema()
otp_logs_schema = OTPLogSchema(many=True)
