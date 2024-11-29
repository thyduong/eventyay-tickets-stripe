/*global $, stripe_pubkey, stripe_loadingmessage, gettext */
'use strict';

var stripeObj = {
    stripe: null,
    elements: null,
    card: null,
    paymentRequest: null,
    paymentRequestButton: null,

    'cc_request': function () {
        waitingDialog.show(gettext("Contacting Stripe …"));
        $(".stripe-errors").hide();

        // ToDo: 'card' --> proper type of payment method
        stripeObj.stripe.createPaymentMethod('card', stripeObj.card).then(function (result) {
            waitingDialog.hide();
            if (result.error) {
                $(".stripe-errors").stop().hide().removeClass("sr-only");
                $(".stripe-errors").html("<div class='alert alert-danger'>" + result.error.message + "</div>");
                $(".stripe-errors").slideDown();
            } else {
                var $form = $("#stripe_payment_method_id").closest("form");
                // var $form = $("#stripe_" + method + "_payment_method_id").closest("form");
                // Insert the token into the form so it gets submitted to the server
                $("#stripe_payment_method_id").val(result.paymentMethod.id);
                $("#stripe_card_brand").val(result.paymentMethod.card.brand);
                $("#stripe_card_last4").val(result.paymentMethod.card.last4);
                // and submit
                $form.get(0).submit();
            }
        });
    },
    'load': function () {
      if (stripeObj.stripe !== null) {
          return;
      }
      $('.stripe-container').closest("form").find(".checkout-button-row .btn-primary").prop("disabled", true);
        $.ajax(
            {
                url: 'https://js.stripe.com/v3/',
                dataType: 'script',
                success: function () {
                    if ($.trim($("#stripe_connectedAccountId").html())) {
                        stripeObj.stripe = Stripe($.trim($("#stripe_pubkey").html()), {
                            stripeAccount: $.trim($("#stripe_connectedAccountId").html()),
                            locale: $.trim($("body").attr("data-locale"))
                        });
                    } else {
                        stripeObj.stripe = Stripe($.trim($("#stripe_pubkey").html()), {
                            locale: $.trim($("body").attr("data-locale"))
                        });
                    }
                    stripeObj.elements = stripeObj.stripe.elements();
                    if ($.trim($("#stripe_merchantcountry").html()) !== "") {
                        try {
                            stripeObj.paymentRequest = stripeObj.stripe.paymentRequest({
                                country: $("#stripe_merchantcountry").html(),
                                currency: $("#stripe_currency").val().toLowerCase(),
                                total: {
                                    label: gettext('Total'),
                                    amount: parseInt($("#stripe_total").val())
                                },
                                displayItems: [],
                                requestPayerName: false,
                                requestPayerEmail: false,
                                requestPayerPhone: false,
                                requestShipping: false,
                            });

                            stripeObj.paymentRequest.on('paymentmethod', function (ev) {
                                ev.complete('success');

                                var $form = $("#stripe_payment_method_id").closest("form");
                                // Insert the token into the form so it gets submitted to the server
                                $("#stripe_payment_method_id").val(ev.paymentMethod.id);
                                $("#stripe_card_brand").val(ev.paymentMethod.card.brand);
                                $("#stripe_card_last4").val(ev.paymentMethod.card.last4);
                                // and submit
                                $form.get(0).submit();
                            });
                        } catch (e) {
                            stripeObj.paymentRequest = null;
                        }
                    } else {
                        stripeObj.paymentRequest = null;
                    }
                    if ($("#stripe-card").length) {
                        stripeObj.card = stripeObj.elements.create('card', {
                            'style': {
                                'base': {
                                    'fontFamily': '"Open Sans","OpenSans","Helvetica Neue",Helvetica,Arial,sans-serif',
                                    'fontSize': '14px',
                                    'color': '#555555',
                                    'lineHeight': '1.42857',
                                    'border': '1px solid #ccc',
                                    '::placeholder': {
                                        color: 'rgba(0,0,0,0.4)',
                                    },
                                },
                                'invalid': {
                                    'color': 'red',
                                },
                            },
                            classes: {
                                focus: 'is-focused',
                                invalid: 'has-error',
                            }
                        });
                        stripeObj.card.mount("#stripe-card");
                    }
                    stripeObj.card.on('ready', function () {
                       $('.stripe-container').closest("form").find(".checkout-button-row .btn-primary").prop("disabled", false);
                    });
                    if ($("#stripe-payment-request-button").length && stripeObj.paymentRequest != null) {
                      stripeObj.paymentRequestButton = stripeObj.elements.create('paymentRequestButton', {
                        paymentRequest: stripeObj.paymentRequest,
                      });

                      stripeObj.paymentRequest.canMakePayment().then(function(result) {
                        if (result) {
                          stripeObj.paymentRequestButton.mount('#stripe-payment-request-button');
                          $('#stripe-elements .stripe-or').removeClass("hidden");
                          $('#stripe-payment-request-button').parent().removeClass("hidden");
                        } else {
                          $('#stripe-payment-request-button').hide();
                          document.getElementById('stripe-payment-request-button').style.display = 'none';
                        }
                      });
                    }
                }
            }
        );
    },

    'confirmCard': function (payment_intent_client_secret) {
        $.ajax({
            url: 'https://js.stripe.com/v3/',
            dataType: 'script',
            success: function () {
                if ($.trim($("#stripe_connectedAccountId").html())) {
                    stripeObj.stripe = Stripe($.trim($("#stripe_pubkey").html()), {
                        stripeAccount: $.trim($("#stripe_connectedAccountId").html()),
                        locale: $.trim($("body").attr("data-locale"))
                    });
                } else {
                    stripeObj.stripe = Stripe($.trim($("#stripe_pubkey").html()), {
                        locale: $.trim($("body").attr("data-locale"))
                    });
                }
                stripeObj.stripe.confirmCard(
                    payment_intent_client_secret
                ).then(function (result) {
                    waitingDialog.show(gettext("Confirming your payment …"));
                    location.reload();
                });
            }
        });
    },
    'confirmCardiFrame': function (payment_intent_next_action_redirect_url) {
        waitingDialog.show(gettext("Contacting your bank …"));
        let iframe = document.createElement('iframe');
        iframe.src = payment_intent_next_action_redirect_url;
        iframe.className = 'embed-responsive-item';
        $('#scacontainer').append(iframe);
        $('#scacontainer iframe').load(function () {
            waitingDialog.hide();
        });
    },
    'redirectToPayment': function (payment_intent_next_action_redirect_url) {
        waitingDialog.show(gettext("Contacting your bank …"));

        let payment_intent_redirect_action_handling = $.trim($("#stripe_payment_intent_redirect_action_handling").html());
        if (payment_intent_redirect_action_handling === 'iframe') {
            let iframe = document.createElement('iframe');
            iframe.src = payment_intent_next_action_redirect_url;
            iframe.className = 'embed-responsive-item';
            $('#scacontainer').append(iframe);
            $('#scacontainer iframe').on("load", function () {
                waitingDialog.hide();
            });
        } else if (payment_intent_redirect_action_handling === 'redirect') {
            window.location.href = payment_intent_next_action_redirect_url;
        }
    },
    'redirectWechatPay': function (payment_intent_client_secret) {
        stripeObj.loadObject(function () {
            stripeObj.stripe.confirmWechatPayPayment(
                payment_intent_client_secret,
                {
                    payment_method_options: {
                        wechat_pay: {
                            client: 'web',
                        },
                    },
                }
            ).then(function (result) {
                if (result.error) {
                    waitingDialog.hide();
                    $(".stripe-errors").stop().hide().removeClass("sr-only");
                    $(".stripe-errors").html("<div class='alert alert-danger'>Technical error, please contact support: " + result.error.message + "</div>");
                    $(".stripe-errors").slideDown();
                } else {
                    waitingDialog.show(gettext("Confirming your payment …"));
                    location.reload();
                }
            });
        });
    },
    'redirectAlipay': function (payment_intent_client_secret) {
        stripeObj.loadObject(function () {
            stripeObj.stripe.confirmAlipayPayment(
                payment_intent_client_secret,
                {
                    return_url: window.location.href
                }
            ).then(function (result) {
                if (result.error) {
                    waitingDialog.hide();
                    $(".stripe-errors").stop().hide().removeClass("sr-only");
                    $(".stripe-errors").html("<div class='alert alert-danger'>Technical error, please contact support: " + result.error.message + "</div>");
                    $(".stripe-errors").slideDown();
                } else {
                    waitingDialog.show(gettext("Confirming your payment …"));
                }
            });
        });
    }
};
$(function () {
    if ($("#stripe_payment_intent_SCA_status").length) {
        let payment_intent_redirect_action_handling = $.trim($("#stripe_payment_intent_redirect_action_handling").html());
        let stt = $.trim($("#order_status").html());
        let url = $.trim($("#order_url").html())
        // show message
        if (payment_intent_redirect_action_handling === 'iframe') {
            window.parent.postMessage('3DS-authentication-complete.' + stt, '*');
            return;
        } else if (payment_intent_redirect_action_handling === 'redirect') {
            waitingDialog.show(gettext("Confirming your payment …"));
            if (stt === 'p') {
                window.location.href = url + '?paid=yes';
            } else {
                window.location.href = url;
            }
        }
    // redirect to payment url: ideal, bancontact, eps, przelewy24
    } else if ($("#stripe_payment_intent_next_action_redirect_url").length) {
        let payment_intent_next_action_redirect_url = $.trim($("#stripe_payment_intent_next_action_redirect_url").html());
        stripeObj.redirectToPayment(payment_intent_next_action_redirect_url);
    // redirect to webchat pay
    } else if ($.trim($("#stripe_payment_intent_action_type").html()) === "wechat_pay_display_qr_code") {
        let payment_intent_client_secret = $.trim($("#stripe_payment_intent_client_secret").html());
        stripeObj.redirectWechatPay(payment_intent_client_secret);
    // redirect to alipay
    } else if ($.trim($("#stripe_payment_intent_action_type").html()) === "alipay_handle_redirect") {
        let payment_intent_client_secret = $.trim($("#stripe_payment_intent_client_secret").html());
        stripeObj.redirectAlipay(payment_intent_client_secret);
    // card payment
    } else if ($("#stripe_payment_intent_client_secret").length) {
        let payment_intent_client_secret = $.trim($("#stripe_payment_intent_client_secret").html());
        stripeObj.confirmCard(payment_intent_client_secret);
    }

    $(window).on("message onmessage", function(e) {
        if (typeof e.originalEvent.data === "string" && e.originalEvent.data.startsWith('3DS-authentication-complete.')) {
            waitingDialog.show(gettext("Confirming your payment …"));
            $('#scacontainer').hide();
            $('#continuebutton').removeClass('hidden');

            if (e.originalEvent.data.split('.')[1] == 'p') {
                window.location.href = $('#continuebutton').attr('href') + '?paid=yes';
            } else {
                window.location.href = $('#continuebutton').attr('href');
            }
        }
    });

    if (!$(".stripe-container").length)
        return;

    if ($("input[name=payment][value=stripe]").is(':checked') || $(".payment-redo-form").length) {
          stripeObj.load();
    } else {
        $("input[name=payment]").change(function () {
            if ($(this).val() === 'stripe') {
                stripeObj.load();
            }
        })
    }

    $("#stripe_other_card").click(
        function (e) {
            $("#stripe_payment_method_id").val("");
            $("#stripe-current-card").slideUp();
            $("#stripe-elements").slideDown();

            e.preventDefault();
            return false;
        }
    );

    if ($("#stripe-current-card").length) {
        $("#stripe-elements").hide();
    }

    $('.stripe-container').closest("form").submit(
        function () {
            if ($("input[name=card_new]").length && !$("input[name=card_new]").prop('checked')) {
                return null;
            }
            if (($("input[name=payment][value=stripe]").prop('checked') || $("input[name=payment][type=radio]").length === 0)
                && $("#stripe_payment_method_id").val() == "") {
                stripeObj.cc_request();
                return false;
            }
        }
    );
});