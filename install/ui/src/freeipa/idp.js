/*
 */

define([
        './ipa',
        './jquery',
        './menu',
        './phases',
        './reg',
        './details',
        './search',
        './entity',
        './dialogs/password'
       ],
            function(IPA, $, menu, phases, reg) {

/**
 * Radius module
 * @class
 * @singleton
 */
var idp = IPA.idp = {};

var make_spec = function() {
return {
    name: 'idp',
    enable_test: function() {
        return true;
    },
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'ipaidpclientid',
                'ipaidpscope',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.idp.details',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        },
                        'ipaidpauthendpoint',
                        'ipaidpdevauthendpoint',
                        'ipaidptokendpoint',
                        'ipaidpuserinfodpoint',
                        'ipaidpkeysendpoint',
                        'ipaidpissuerurl',
                        'ipaidpclientid',
			 {
                            name:'ipaidpclientsecret',
                            flags: ['w_if_no_aci']
                         }
                    ]
                }
            ],
            actions: [
                {
                    $type: 'password',
                    dialog: {
                        password_name: 'ipaidpclientsecret'
                    }
                }
            ],
            header_actions: ['password']
        }
    ],
    adder_dialog: {
        title: '@i18n:objects.idp.add',
        fields: [
            'cn',
            {
                label: '@i18n:idp.provider',
		name: 'ipaidpprovider',
		$type: 'select',
		options: IPA.create_options(['', 'google', 'github', 'microsoft', 'okta', 'keycloak'])
            },
            'ipaidpclientid',
            {
                $type: 'password',
                name: 'ipaidpclientsecret'
            },
            {
                $type: 'password',
                name: 'secret_verify',
                label: '@i18n:password.verify_password',
                flags: ['no_command'],
                required: true,
                validators: [{
                    $type: 'same_password',
                    other_field: 'ipaidpclientsecret'
                }]
            },
            'ipaidpscope',
            'ipaidpsub'
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.idp.remove'
    }
};};

/**
 * Radius specification object
 */
idp.spec = make_spec();

/**
 * Register radiusproxy entity
 */
idp.register = function() {
    var e = reg.entity;
    e.register({type: 'idp', spec: idp.spec});
};

phases.on('registration', idp.register);

return idp;
});
